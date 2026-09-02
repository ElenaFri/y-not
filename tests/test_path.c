#include "../include/path.h"
#include "testlib.h"

#include <acl/libacl.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int main(void)
{
    path_free(NULL); /* must be silent */

    /* NULL input is rejected */
    CHECK(path_resolve(NULL) == NULL);

    /* root alone */
    AccessPath *root = path_resolve("/");
    CHECK(root != NULL);
    if (root)
    {
        CHECK(root->count == 1);
        CHECK(strcmp(root->components[0].path, "/") == 0);
        CHECK(root->components[0].denial_reason == REASON_NONE);
        CHECK(S_ISDIR(root->components[0].st.st_mode));
        path_free(root);
    }

    /* /var : 2 components, a reliable non world-writable directory */
    AccessPath *tmp = path_resolve("/var");
    CHECK(tmp != NULL);
    if (tmp)
    {
        CHECK(tmp->count == 2);
        CHECK(strcmp(tmp->components[0].path, "/") == 0);
        CHECK(strcmp(tmp->components[1].path, "/var") == 0);
        CHECK(tmp->components[1].denial_reason == REASON_NONE);
        path_free(tmp);
    }

    /* /usr/bin/ls : 4 components */
    AccessPath *ls = path_resolve("/usr/bin/ls");
    CHECK(ls != NULL);
    if (ls)
    {
        CHECK(ls->count == 4);
        CHECK(strcmp(ls->components[1].path, "/usr") == 0);
        CHECK(strcmp(ls->components[2].path, "/usr/bin") == 0);
        CHECK(strcmp(ls->components[3].path, "/usr/bin/ls") == 0);
        CHECK(ls->components[3].denial_reason == REASON_NONE);
        path_free(ls);
    }

    /* special file : /dev/null is guaranteed to exist on any Linux system */
    AccessPath *devnull = path_resolve("/dev/null");
    CHECK(devnull != NULL);
    if (devnull)
    {
        PathComponent *last = &devnull->components[devnull->count - 1];
        CHECK(last->denial_reason == REASON_NONE);
        CHECK(S_ISCHR(last->st.st_mode));
        CHECK(!last->is_symlink);
        path_free(devnull);
    }

    /* non-existent path : last component marked NOT_FOUND */
    AccessPath *nope = path_resolve("/var/__y_not_no_such_path__");
    CHECK(nope != NULL);
    if (nope)
    {
        CHECK(nope->count == 3);
        CHECK(strcmp(nope->components[2].path, "/var/__y_not_no_such_path__") == 0);
        CHECK(nope->components[1].denial_reason == REASON_NONE);
        CHECK(nope->components[2].denial_reason == REASON_NOT_FOUND);
        path_free(nope);
    }

    /* a middle component that is a regular file, not a directory : ENOTDIR,
       distinct from the plain ENOENT case above */
    AccessPath *notdir = path_resolve("/etc/passwd/impossible");
    CHECK(notdir != NULL);
    if (notdir)
    {
        PathComponent *last = &notdir->components[notdir->count - 1];
        CHECK(last->denial_reason == REASON_NOT_FOUND);
        path_free(notdir);
    }

    /* a directory with no execute bit cannot even be stat()'d into : the
       process itself (not just the simulated "user") gets EACCES from the
       kernel. root is exempt from this check, so skip when running as root. */
    if (geteuid() != 0)
    {
        char blocked_dir[256];
        snprintf(blocked_dir, sizeof(blocked_dir), "%s/y_not_test_noexec_XXXXXX", P_tmpdir);
        CHECK(mkdtemp(blocked_dir) != NULL);

        char inner_file[300];
        snprintf(inner_file, sizeof(inner_file), "%s/file", blocked_dir);
        int fd = open(inner_file, O_CREAT | O_EXCL | O_WRONLY, 0600);
        CHECK(fd != -1);
        if (fd != -1)
            close(fd);

        CHECK(chmod(blocked_dir, 0000) == 0);

        AccessPath *blocked = path_resolve(inner_file);
        CHECK(blocked != NULL);
        if (blocked)
        {
            PathComponent *last = &blocked->components[blocked->count - 1];
            CHECK(last->denial_reason == REASON_NOT_TRAVERSABLE);
            path_free(blocked);
        }

        chmod(blocked_dir, 0700); /* restore so cleanup can remove it */
        unlink(inner_file);
        rmdir(blocked_dir);
    }

    /* normalization: . removed */
    AccessPath *dot = path_resolve("/usr/./bin/ls");
    CHECK(dot != NULL);
    if (dot)
    {
        CHECK(dot->count == 4);
        CHECK(strcmp(dot->components[3].path, "/usr/bin/ls") == 0);
        path_free(dot);
    }

    /* normalization: .. resolved */
    AccessPath *dotdot = path_resolve("/usr/bin/../bin/ls");
    CHECK(dotdot != NULL);
    if (dotdot)
    {
        CHECK(dotdot->count == 4);
        CHECK(strcmp(dotdot->components[3].path, "/usr/bin/ls") == 0);
        path_free(dotdot);
    }

    /* normalization: cannot go above the root */
    AccessPath *above = path_resolve("/../usr/bin/ls");
    CHECK(above != NULL);
    if (above)
    {
        CHECK(above->count == 4);
        CHECK(strcmp(above->components[1].path, "/usr") == 0);
        path_free(above);
    }

    /* normalization: repeated leading .. still clamps at the root */
    AccessPath *above_many = path_resolve("/../../../usr");
    CHECK(above_many != NULL);
    if (above_many)
    {
        CHECK(above_many->count == 2);
        CHECK(strcmp(above_many->components[1].path, "/usr") == 0);
        path_free(above_many);
    }

    /* normalization: going up from a real subdir collapses exactly to root */
    AccessPath *up_to_root = path_resolve("/usr/..");
    CHECK(up_to_root != NULL);
    if (up_to_root)
    {
        CHECK(up_to_root->count == 1);
        CHECK(strcmp(up_to_root->components[0].path, "/") == 0);
        path_free(up_to_root);
    }

    /* normalization: "..." is a literal name, not a shorthand for anything */
    AccessPath *literal_dots = path_resolve("/usr/.../bin");
    CHECK(literal_dots != NULL);
    if (literal_dots)
    {
        CHECK(literal_dots->count == 4);
        CHECK(strcmp(literal_dots->components[2].path, "/usr/...") == 0);
        CHECK(strcmp(literal_dots->components[3].path, "/usr/.../bin") == 0);
        path_free(literal_dots);
    }

    /* many consecutive slashes collapse to a single separator */
    AccessPath *slashes = path_resolve("////");
    CHECK(slashes != NULL);
    if (slashes)
    {
        CHECK(slashes->count == 1);
        CHECK(strcmp(slashes->components[0].path, "/") == 0);
        path_free(slashes);
    }

    /* absolute input longer than PATH_MAX is rejected, not truncated */
    {
        char *huge = malloc(PATH_MAX + 64);
        CHECK(huge != NULL);
        if (huge)
        {
            huge[0] = '/';
            memset(huge + 1, 'a', PATH_MAX + 2);
            huge[PATH_MAX + 3] = '\0';
            CHECK(path_resolve(huge) == NULL);
            free(huge);
        }
    }

    /* relative input whose length alone already exceeds PATH_MAX is rejected too */
    {
        char *huge_rel = malloc(PATH_MAX + 64);
        CHECK(huge_rel != NULL);
        if (huge_rel)
        {
            memset(huge_rel, 'a', PATH_MAX);
            huge_rel[PATH_MAX] = '\0';
            CHECK(path_resolve(huge_rel) == NULL);
            free(huge_rel);
        }
    }

    /* relative path : resolved against the current working directory */
    CHECK(chdir("/usr/bin") == 0);
    AccessPath *rel = path_resolve("ls");
    CHECK(rel != NULL);
    if (rel)
    {
        CHECK(rel->count == 4);
        CHECK(strcmp(rel->components[3].path, "/usr/bin/ls") == 0);
        path_free(rel);
    }

    /* empty input and "." both resolve to the current working directory */
    AccessPath *empty = path_resolve("");
    CHECK(empty != NULL);
    if (empty)
    {
        CHECK(strcmp(empty->components[empty->count - 1].path, "/usr/bin") == 0);
        path_free(empty);
    }
    AccessPath *cur = path_resolve(".");
    CHECK(cur != NULL);
    if (cur)
    {
        CHECK(strcmp(cur->components[cur->count - 1].path, "/usr/bin") == 0);
        path_free(cur);
    }

    /* ".." from a known cwd resolves to its parent */
    AccessPath *parent = path_resolve("..");
    CHECK(parent != NULL);
    if (parent)
    {
        CHECK(strcmp(parent->components[parent->count - 1].path, "/usr") == 0);
        path_free(parent);
    }

    /* Use the compile-time P_tmpdir constant rather than the TMPDIR
       environment variable, which static analyzers flag as attacker-
       influenceable when used to build a filesystem path. */
    char tmpdir[256];
    snprintf(tmpdir, sizeof(tmpdir), "%s/y_not_test_XXXXXX", P_tmpdir);
    CHECK(mkdtemp(tmpdir) != NULL);

    char path_plain[sizeof(tmpdir) + 16];
    snprintf(path_plain, sizeof(path_plain), "%s/plain", tmpdir);

    /* no ACL on a plain file : component.acl stays NULL */
    int fd_plain = open(path_plain, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd_plain != -1);
    if (fd_plain != -1)
    {
        close(fd_plain);
        AccessPath *plain = path_resolve(path_plain);
        CHECK(plain != NULL);
        if (plain)
        {
            CHECK(plain->components[plain->count - 1].acl == NULL);
            path_free(plain);
        }
        unlink(path_plain);
    }

    char path_acl[sizeof(tmpdir) + 16];
    snprintf(path_acl, sizeof(path_acl), "%s/acl", tmpdir);

    /* extended ACL on a file : component.acl is populated */
    int fd_acl = open(path_acl, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd_acl != -1);
    if (fd_acl != -1)
    {
        close(fd_acl);
        acl_t new_acl = acl_from_text("user::rw-,user:0:r--,group::---,mask::r--,other::---");
        CHECK(new_acl != NULL);
        if (new_acl)
        {
            CHECK(acl_set_file(path_acl, ACL_TYPE_ACCESS, new_acl) == 0);
            acl_free(new_acl);

            AccessPath *withacl = path_resolve(path_acl);
            CHECK(withacl != NULL);
            if (withacl)
            {
                CHECK(withacl->components[withacl->count - 1].acl != NULL);
                path_free(withacl);
            }
        }
        unlink(path_acl);
    }

    char path_nocap[sizeof(tmpdir) + 16];
    snprintf(path_nocap, sizeof(path_nocap), "%s/nocap", tmpdir);

    /* no file capability set : component.file_caps stays NULL */
    int fd_nocap = open(path_nocap, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd_nocap != -1);
    if (fd_nocap != -1)
    {
        close(fd_nocap);
        AccessPath *nocap = path_resolve(path_nocap);
        CHECK(nocap != NULL);
        if (nocap)
        {
            CHECK(nocap->components[nocap->count - 1].file_caps == NULL);
            path_free(nocap);
        }
        unlink(path_nocap);
    }

    /* setting a file capability requires CAP_SETFCAP (root); skip otherwise */
    if (geteuid() == 0)
    {
        char path_cap[sizeof(tmpdir) + 16];
        snprintf(path_cap, sizeof(path_cap), "%s/withcap", tmpdir);

        int fd_cap = open(path_cap, O_CREAT | O_EXCL | O_WRONLY, 0700);
        CHECK(fd_cap != -1);
        if (fd_cap != -1)
        {
            close(fd_cap);
            cap_t new_cap = cap_from_text("cap_net_bind_service=ep");
            CHECK(new_cap != NULL);
            if (new_cap)
            {
                CHECK(cap_set_file(path_cap, new_cap) == 0);
                cap_free(new_cap);

                AccessPath *withcap = path_resolve(path_cap);
                CHECK(withcap != NULL);
                if (withcap)
                {
                    PathComponent *last = &withcap->components[withcap->count - 1];
                    CHECK(last->file_caps != NULL);
                    if (last->file_caps)
                        CHECK(strstr(last->file_caps, "cap_net_bind_service") != NULL);
                    path_free(withcap);
                }
            }
            unlink(path_cap);
        }
    }

    char path_target[sizeof(tmpdir) + 16];
    snprintf(path_target, sizeof(path_target), "%s/target", tmpdir);
    char path_link[sizeof(tmpdir) + 16];
    snprintf(path_link, sizeof(path_link), "%s/link", tmpdir);

    /* symlink to an existing target : resolved, is_symlink set, target recorded */
    int fd_target = open(path_target, O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd_target != -1);
    if (fd_target != -1)
    {
        close(fd_target);
        CHECK(symlink(path_target, path_link) == 0);

        AccessPath *link = path_resolve(path_link);
        CHECK(link != NULL);
        if (link)
        {
            PathComponent *last = &link->components[link->count - 1];
            CHECK(last->denial_reason == REASON_NONE);
            CHECK(last->is_symlink);
            CHECK(last->symlink_target != NULL && strcmp(last->symlink_target, path_target) == 0);
            CHECK(S_ISREG(last->st.st_mode)); /* stat() followed the link */
            path_free(link);
        }
        unlink(path_link);
        unlink(path_target);
    }

    char path_broken[sizeof(tmpdir) + 16];
    snprintf(path_broken, sizeof(path_broken), "%s/broken", tmpdir);

    /* symlink to a non-existent target : REASON_BROKEN_SYMLINK */
    CHECK(symlink("/y_not_no_such_target_xyz", path_broken) == 0);
    AccessPath *broken = path_resolve(path_broken);
    CHECK(broken != NULL);
    if (broken)
    {
        PathComponent *last = &broken->components[broken->count - 1];
        CHECK(last->is_symlink);
        CHECK(last->denial_reason == REASON_BROKEN_SYMLINK);
        path_free(broken);
    }
    unlink(path_broken);

    char path_loop_a[sizeof(tmpdir) + 16], path_loop_b[sizeof(tmpdir) + 16];
    snprintf(path_loop_a, sizeof(path_loop_a), "%s/loop_a", tmpdir);
    snprintf(path_loop_b, sizeof(path_loop_b), "%s/loop_b", tmpdir);

    /* two symlinks pointing at each other : REASON_SYMLINK_LOOP */
    CHECK(symlink(path_loop_b, path_loop_a) == 0);
    CHECK(symlink(path_loop_a, path_loop_b) == 0);
    AccessPath *loop = path_resolve(path_loop_a);
    CHECK(loop != NULL);
    if (loop)
    {
        PathComponent *last = &loop->components[loop->count - 1];
        CHECK(last->denial_reason == REASON_SYMLINK_LOOP);
        path_free(loop);
    }
    unlink(path_loop_a);
    unlink(path_loop_b);

    rmdir(tmpdir);

    return TEST_SUMMARY();
}
