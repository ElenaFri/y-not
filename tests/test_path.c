#include "../include/path.h"
#include "testlib.h"

#include <acl/libacl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

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

    /* no ACL on a plain file : component.acl stays NULL */
    char tmpl_plain[] = "/tmp/y_not_test_plain_XXXXXX";
    int fd_plain = mkstemp(tmpl_plain);
    CHECK(fd_plain != -1);
    if (fd_plain != -1)
    {
        close(fd_plain);
        AccessPath *plain = path_resolve(tmpl_plain);
        CHECK(plain != NULL);
        if (plain)
        {
            CHECK(plain->components[plain->count - 1].acl == NULL);
            path_free(plain);
        }
        unlink(tmpl_plain);
    }

    /* extended ACL on a file : component.acl is populated */
    char tmpl_acl[] = "/tmp/y_not_test_acl_XXXXXX";
    int fd_acl = mkstemp(tmpl_acl);
    CHECK(fd_acl != -1);
    if (fd_acl != -1)
    {
        close(fd_acl);
        acl_t new_acl = acl_from_text("user::rw-,user:0:r--,group::---,mask::r--,other::---");
        CHECK(new_acl != NULL);
        if (new_acl)
        {
            CHECK(acl_set_file(tmpl_acl, ACL_TYPE_ACCESS, new_acl) == 0);
            acl_free(new_acl);

            AccessPath *withacl = path_resolve(tmpl_acl);
            CHECK(withacl != NULL);
            if (withacl)
            {
                CHECK(withacl->components[withacl->count - 1].acl != NULL);
                path_free(withacl);
            }
        }
        unlink(tmpl_acl);
    }

    return TEST_SUMMARY();
}
