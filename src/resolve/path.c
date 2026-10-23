#define _GNU_SOURCE
#include "resolve/path.h"

#include <acl/libacl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include "context/selinux_info.h"

/* PATH_MAX may be absent on systems without a fixed path limit */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void free_component(PathComponent *c)
{
    free(c->path);
    free(c->symlink_target);
    free(c->file_caps);
    free(c->selinux_context);
    if (c->acl)
        acl_free(c->acl);
}

static char *read_symlink_target(const char *path)
{
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n < 0)
        return NULL;
    buf[n] = '\0';
    return strdup(buf);
}

static char *read_file_caps(const char *path)
{
    cap_t cap = cap_get_file(path);
    if (!cap)
        return NULL;
    char *text = cap_to_text(cap, NULL);
    char *owned = text ? strdup(text) : NULL;
    if (text)
        cap_free(text);
    cap_free(cap);
    return owned;
}

static void inspect_component(PathComponent *c)
{
    struct stat lst;
    if (lstat(c->path, &lst) == -1)
    {
        c->denial_reason = (errno == ENOENT || errno == ENOTDIR)
                               ? REASON_NOT_FOUND
                               : REASON_NOT_TRAVERSABLE;
        return;
    }

    c->link_st = lst;
    c->link_st_known = true;

    if (S_ISLNK(lst.st_mode))
    {
        c->is_symlink = true;
        c->symlink_target = read_symlink_target(c->path);
    }

    /* Follow the symlink (if any) to get the info permission checks need;
       the kernel does the same when traversing or opening a path. */
    if (stat(c->path, &c->st) == -1)
    {
        if (errno == ELOOP)
            c->denial_reason = REASON_SYMLINK_LOOP;
        else if (c->is_symlink && (errno == ENOENT || errno == ENOTDIR))
            c->denial_reason = REASON_BROKEN_SYMLINK;
        else
            c->denial_reason = (errno == ENOENT || errno == ENOTDIR)
                                   ? REASON_NOT_FOUND
                                   : REASON_NOT_TRAVERSABLE;
        return;
    }

    struct statvfs mount_info;
    if (statvfs(c->path, &mount_info) == 0)
    {
        c->mount_flags_known = true;
        c->mount_read_only = (mount_info.f_flag & ST_RDONLY) != 0;
        c->mount_noexec = (mount_info.f_flag & ST_NOEXEC) != 0;
        c->mount_nosuid = (mount_info.f_flag & ST_NOSUID) != 0;
    }

    if (acl_extended_file(c->path) == 1)
        c->acl = acl_get_file(c->path, ACL_TYPE_ACCESS);

    if (S_ISREG(c->st.st_mode))
        c->file_caps = read_file_caps(c->path);

    c->selinux_context = selinux_file_context(c->path);
}

static int build_abs(const char *input, char *buf, size_t size)
{
    size_t ilen = strlen(input);
    if (ilen == 0)
    {
        errno = ENOENT;
        return -1;
    }
    if (*input == '/')
    {
        if (ilen >= size)
            return -1;
        memcpy(buf, input, ilen + 1);
    }
    else
    {
        char *cwd = getcwd(buf, size);
        if (!cwd)
            return -1;
        size_t clen = strlen(cwd);
        if (clen + 1 + ilen >= size)
            return -1;
        cwd[clen] = '/';
        memcpy(cwd + clen + 1, input, ilen + 1);
    }
    return 0;
}

/* Inspect each lexical prefix without resolving . or .. ourselves. The
   kernel resolves symlinks before interpreting a following .., so collapsing
   those segments textually can inspect a different object than the caller
   named (for example, /a/link/../file). Repeated separators are harmless and
   are omitted from the component list. */
static bool fill_components(PathComponent *comp, size_t capacity,
                            const char *abs, size_t len)
{
    comp[0].path = strdup("/");
    if (!comp[0].path)
        return false;
    inspect_component(&comp[0]);

    char prefix[PATH_MAX];
    size_t plen = 1;
    prefix[0] = '/';
    prefix[1] = '\0';
    size_t ci = 1;

    for (size_t i = 1; i < len;)
    {
        while (i < len && abs[i] == '/')
            i++;
        if (i == len)
            break;

        size_t start = i;
        while (i < len && abs[i] != '/')
            i++;
        size_t segment_len = i - start;
        if (plen > 1)
            prefix[plen++] = '/';
        if (plen + segment_len >= sizeof(prefix) || ci >= capacity)
            return false;
        memcpy(prefix + plen, abs + start, segment_len);
        plen += segment_len;
        prefix[plen] = '\0';

        comp[ci].path = strdup(prefix);
        if (!comp[ci].path)
            return false;
        inspect_component(&comp[ci]);
        ci++;
    }

    /* A trailing slash requires the final component to resolve as a directory.
       Keep it in the final syscall path while avoiding a duplicate trace row. */
    if (len > 1 && abs[len - 1] == '/' && ci > 1)
    {
        if (plen + 1 >= sizeof(prefix))
            return false;
        prefix[plen++] = '/';
        prefix[plen] = '\0';
        char *with_slash = strdup(prefix);
        if (!with_slash)
            return false;
        free_component(&comp[ci - 1]);
        comp[ci - 1] = (PathComponent){.path = with_slash};
        inspect_component(&comp[ci - 1]);
    }
    return true;
}

AccessPath *path_resolve(const char *input)
{
    if (!input)
        return NULL;

    char abs[PATH_MAX];
    if (build_abs(input, abs, sizeof(abs)) != 0)
        return NULL;

    size_t len = strlen(abs);

    /* One trace entry for root plus one for each non-empty path segment.
       Unlike counting separators, this also handles repeated/trailing '/'. */
    size_t count = 1;
    for (size_t i = 1; i < len;)
    {
        while (i < len && abs[i] == '/')
            i++;
        if (i == len)
            break;
        count++;
        while (i < len && abs[i] != '/')
            i++;
    }

    AccessPath *ap = malloc(sizeof(*ap));
    if (!ap)
        return NULL;

    ap->count = count;
    ap->components = calloc(count, sizeof(PathComponent));
    if (!ap->components)
    {
        free(ap);
        return NULL;
    }

    if (fill_components(ap->components, count, abs, len))
        return ap;

    /* fill failed: free explicitly so the analyser can track ap */
    for (size_t i = 0; i < count; i++)
        free_component(&ap->components[i]);
    free(ap->components);
    free(ap);
    return NULL;
}

void path_free(AccessPath *ap)
{
    if (!ap)
        return;
    if (ap->components)
    {
        for (size_t i = 0; i < ap->count; i++)
            free_component(&ap->components[i]);
        free(ap->components);
    }
    free(ap);
}
