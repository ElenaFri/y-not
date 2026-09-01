#include "../include/output.h"
#include "../include/access.h"
#include "../include/user.h"
#include "testlib.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Regression test: rendering a very deeply nested path must not overflow
   any fixed-size buffer (a stack buffer overflow was found and fixed here
   for paths with hundreds of components). */
static void check_deep_tree_does_not_crash(void)
{
    enum
    {
        DEPTH = 2000
    };

    PathComponent *comps = calloc(DEPTH, sizeof(PathComponent));
    CHECK(comps != NULL);
    if (!comps)
        return;

    for (int i = 0; i < DEPTH; i++)
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "seg%d", i);
        comps[i].path = strdup(buf);
        comps[i].st.st_mode = S_IFDIR | 0755;
        comps[i].can_execute = true;
    }

    AccessPath ap = {.components = comps, .count = DEPTH};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .groups = NULL, .group_count = 0, .name = "test"};

    /* Silence the tree output: this only checks that it doesn't crash. */
    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    render_result_text(&result, &user, ACCESS_READ);

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);

    CHECK(true); /* reaching here means no crash */

    for (int i = 0; i < DEPTH; i++)
        free(comps[i].path);
    free(comps);
}

/* Regression check: when path_resolve() itself fails (NULL input, or a
   path too long to even build), check_access() returns an AccessResult
   with access_path == NULL and blocked_path == NULL. The renderer must
   handle that without dereferencing anything. */
static void check_null_access_path_does_not_crash(void)
{
    AccessResult result = {.allowed = false, .reason = REASON_NOT_FOUND, .blocked_path = NULL, .access_path = NULL};
    User user = {.uid = 1000, .primary_gid = 1000, .groups = NULL, .group_count = 0, .name = "test"};

    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    render_result_text(&result, &user, ACCESS_READ);

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);

    CHECK(true); /* reaching here means no crash */
}

int main(void)
{
    check_deep_tree_does_not_crash();
    check_null_access_path_does_not_crash();
    return TEST_SUMMARY();
}
