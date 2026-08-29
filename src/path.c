#include "path.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* PATH_MAX may be absent on systems without a fixed path limit */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void stat_component(PathComponent *c)
{
    if (stat(c->path, &c->st) != -1)
        return;
    c->denial_reason = (errno == ENOENT || errno == ENOTDIR)
                           ? REASON_NOT_FOUND
                           : REASON_NOT_TRAVERSABLE;
}

static int build_abs(const char *input, char *buf, size_t size)
{
    size_t ilen = strlen(input);
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

/* Returns false on the first allocation failure; already-set paths remain valid. */
static bool fill_components(PathComponent *comp, size_t count,
                            const char *abs, size_t len)
{
    comp[0].path = strdup("/");
    if (!comp[0].path)
        return false;
    stat_component(&comp[0]);
    if (len <= 1)
        return true;

    size_t ci = 1;
    for (size_t i = 1; i < len && ci < count; i++)
    {
        if (abs[i] == '/')
        {
            comp[ci].path = strndup(abs, i);
            if (!comp[ci].path)
                return false;
            stat_component(&comp[ci]);
            ci++;
        }
    }
    comp[count - 1].path = strdup(abs);
    if (!comp[count - 1].path)
        return false;
    stat_component(&comp[count - 1]);
    return true;
}

/* Resolve . and .. segments in an absolute path, in-place. */
static void normalize_abs(char *path)
{
    char buf[PATH_MAX];
    char *dst = buf + 1;
    const char *src = path + 1;
    buf[0] = '/';

    while (*src)
    {
        while (*src == '/')
            src++;
        if (!*src)
            break;

        const char *seg = src;
        while (*src && *src != '/')
            src++;
        size_t slen = (size_t)(src - seg);

        if (slen == 1 && *seg == '.')
            continue;

        if (slen == 2 && seg[0] == '.' && seg[1] == '.')
        {
            if (dst > buf + 1)
            {
                dst--;
                while (*(dst - 1) != '/')
                    dst--;
            }
            continue;
        }

        if (*(dst - 1) != '/')
            *dst++ = '/';
        memcpy(dst, seg, slen);
        dst += slen;
    }
    *dst = '\0';
    memcpy(path, buf, (size_t)(dst - buf + 1));
}

AccessPath *path_resolve(const char *input)
{
    if (!input)
        return NULL;

    char abs[PATH_MAX];
    if (build_abs(input, abs, sizeof(abs)) != 0)
        return NULL;

    normalize_abs(abs);

    size_t len = strlen(abs);

    size_t count = 1;
    if (len > 1)
    {
        for (size_t i = 1; i < len; i++)
            if (abs[i] == '/')
                count++;
        count++;
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
        free(ap->components[i].path);
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
            free(ap->components[i].path);
        free(ap->components);
    }
    free(ap);
}
