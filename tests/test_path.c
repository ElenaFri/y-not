#include "../include/path.h"
#include "testlib.h"

#include <string.h>
#include <sys/stat.h>

int main(void)
{
    path_free(NULL); /* doit être silencieux */

    /* racine seule */
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

    /* /var : 2 composants, répertoire fiable et non world-writable */
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

    /* /usr/bin/ls : 4 composants */
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

    /* chemin inexistant : dernier composant marqué NOT_FOUND */
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

    return TEST_SUMMARY();
}
