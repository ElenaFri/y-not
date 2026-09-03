#include "../include/render/output.h"
#include "../include/access.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Every render_result_text() call in this file goes through stdout; none of
   these tests care about the printed text, only that nothing crashes while
   exercising a given code path (buffer arithmetic, switch cases, etc). */
static void render_silently(const AccessResult *result, const User *user, AccessOperation op)
{
    fflush(stdout); /* flush anything buffered before fd 1 changes meaning */
    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    render_result_text(result, user, op);

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
}

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

    render_silently(&result, &user, ACCESS_READ);
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

    render_silently(&result, &user, ACCESS_READ);
    CHECK(true); /* reaching here means no crash */
}

/* Builds a 2-component tree (root + target) mirroring exactly what
   access.c produces on a real denial: both the AccessResult and the
   blocked PathComponent carry the same reason. */
static const AccessReason g_reasons[] = {
    REASON_OWNER_DENIED,
    REASON_GROUP_DENIED,
    REASON_GROUP_MISSING,
    REASON_OTHER_DENIED,
    REASON_ACL_DENIED,
    REASON_NOT_TRAVERSABLE,
    REASON_NOT_FOUND,
    REASON_BROKEN_SYMLINK,
    REASON_SYMLINK_LOOP,
};

/* Every AccessReason must produce a distinct, crash-free message, and the
   blocked component must render its "(not found)"-style short form when
   applicable, or a normal permission row (marked BLOCKED) otherwise. */
static void check_every_reason_message(void)
{
    for (size_t i = 0; i < sizeof(g_reasons) / sizeof(g_reasons[0]); i++)
    {
        PathComponent comps[2] = {0};
        comps[0].path = strdup("/");
        comps[0].st.st_mode = S_IFDIR | 0755;
        comps[0].can_execute = true;

        comps[1].path = strdup("/target");
        comps[1].st.st_mode = S_IFREG | 0644;
        comps[1].st.st_uid = 999999; /* unresolvable: exercises the numeric fallback */
        comps[1].st.st_gid = 999999;
        comps[1].denial_reason = g_reasons[i];

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = false, .reason = g_reasons[i], .blocked_path = comps[1].path, .access_path = &ap};
        User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

        /* alternate operations so op_name()'s write branch is exercised too */
        render_silently(&result, &user, (i % 2) ? ACCESS_WRITE : ACCESS_READ);
        CHECK(true);

        free(comps[0].path);
        free(comps[1].path);
    }
}

/* file_type_char() must render every Unix file type, and a symlinked
   component must show the "name -> target" arrow form. */
static void check_file_types_and_symlink_arrow(void)
{
    const mode_t types[] = {S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK};

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    {
        PathComponent comps[2] = {0};
        comps[0].path = strdup("/");
        comps[0].st.st_mode = S_IFDIR | 0755;
        comps[0].can_execute = true;

        comps[1].path = strdup("/target");
        comps[1].st.st_mode = types[i] | 0644;
        comps[1].can_read = true;
        if (types[i] == S_IFLNK)
        {
            comps[1].is_symlink = true;
            comps[1].symlink_target = strdup("/elsewhere");
        }

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
        User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

        render_silently(&result, &user, ACCESS_READ);
        CHECK(true);

        free(comps[0].path);
        free(comps[1].path);
        free(comps[1].symlink_target);
    }
}

/* Optional per-component annotations (file capabilities, SELinux context)
   must be appended to the row without disturbing anything else. */
static void check_file_caps_and_selinux_annotations(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0755;
    comps[1].can_execute = true;
    comps[1].file_caps = strdup("cap_net_bind_service=ep");
    comps[1].selinux_context = strdup("unconfined_u:object_r:user_home_t:s0");

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, ACCESS_EXECUTE);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
    free(comps[1].file_caps);
    free(comps[1].selinux_context);
}

/* Once the blocked component has been printed, every component after it
   is skipped (label only, no permission details) - a 2-component tree
   can never exercise that "skip" branch since the blocked one is last. */
static void check_component_after_the_blocked_one(void)
{
    PathComponent comps[3] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/blocked");
    comps[1].st.st_mode = S_IFDIR | 0755;
    comps[1].denial_reason = REASON_OWNER_DENIED;

    comps[2].path = strdup("/blocked/after");
    comps[2].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 3};
    AccessResult result = {.allowed = false, .reason = REASON_OWNER_DENIED, .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, ACCESS_READ);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
    free(comps[2].path);
}

/* AccessOperation/AccessReason are complete enums in practice, but the
   switches have a defensive default case that should never crash if it
   were ever reached (e.g. after adding a new enum value without updating
   the renderer). */
static void check_defensive_default_cases(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0644;
    comps[1].denial_reason = (AccessReason)999;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = (AccessReason)999, .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, (AccessOperation)999);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
}

int main(void)
{
    check_deep_tree_does_not_crash();
    check_null_access_path_does_not_crash();
    check_every_reason_message();
    check_file_types_and_symlink_arrow();
    check_file_caps_and_selinux_annotations();
    check_component_after_the_blocked_one();
    check_defensive_default_cases();
    return TEST_SUMMARY();
}
