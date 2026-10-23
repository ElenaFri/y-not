#include "../include/render/explanation.h"
#include "testlib.h"

#include <grp.h>
#include <string.h>

static struct group mock_group = {.gr_name = "y_not_test_group", .gr_gid = 1234};

struct group *getgrgid(gid_t gid)
{
    return gid == mock_group.gr_gid ? &mock_group : NULL;
}

static void check_explanation(AccessReason reason, AccessOperation op,
                              PermissionResult permission, gid_t file_gid,
                              bool blocked_on_traversal, const char *expected)
{
    PathComponent components[2] = {0};
    components[0].path = "/";
    components[0].st.st_mode = S_IFDIR | 0755;
    components[1].path = "/target";
    components[1].st.st_mode = (blocked_on_traversal ? S_IFDIR : S_IFREG) | 0640;
    components[1].st.st_gid = file_gid;
    components[1].checked_permission = permission;
    components[1].checked_permission_known = true;

    AccessPath access_path = {.components = components, .count = 2};
    AccessResult result = {
        .allowed = false,
        .reason = reason,
        .blocked_on_traversal = blocked_on_traversal,
        .blocked_path = components[1].path,
        .access_path = &access_path,
    };
    char actual[256];
    format_access_explanation(&result, op, actual, sizeof(actual));
    CHECK(strcmp(actual, expected) == 0);
}

int main(void)
{
    check_explanation(
        REASON_GROUP_MISSING, ACCESS_READ,
        (PermissionResult){
            .reason = REASON_GROUP_MISSING,
            .source = PERMISSION_SOURCE_ACL_OTHER,
            .missing_group_gid = 1234,
            .missing_group_known = true,
            .candidate_group_gids = {1234},
            .candidate_group_count = 1,
        },
        5678, false,
        "not in group \"y_not_test_group\" (which would allow read)");

    /* Several candidate groups: a plural phrasing lists each, named or numeric. */
    check_explanation(
        REASON_GROUP_MISSING, ACCESS_READ,
        (PermissionResult){
            .reason = REASON_GROUP_MISSING,
            .source = PERMISSION_SOURCE_ACL_OTHER,
            .missing_group_gid = 1234,
            .missing_group_known = true,
            .candidate_group_gids = {1234, 9999},
            .candidate_group_count = 2,
        },
        5678, false,
        "not in any of the groups that would allow read: "
        "\"y_not_test_group\", \"9999\"");

    check_explanation(
        REASON_GROUP_MISSING, ACCESS_WRITE,
        (PermissionResult){
            .reason = REASON_GROUP_MISSING,
            .source = PERMISSION_SOURCE_UNIX_OTHER,
            .missing_group_gid = 2345,
            .missing_group_known = true,
        },
        5678, false,
        "not in group \"2345\" (which would allow write)");

    check_explanation(
        REASON_GROUP_MISSING, ACCESS_READ,
        (PermissionResult){
            .reason = REASON_GROUP_MISSING,
            .source = PERMISSION_SOURCE_ACL_OTHER,
        },
        1234, false,
        "not in group \"?\" (which would allow read)");

    check_explanation(
        REASON_GROUP_DENIED, ACCESS_WRITE,
        (PermissionResult){
            .reason = REASON_GROUP_DENIED,
            .source = PERMISSION_SOURCE_UNIX_GROUP,
        },
        1234, false,
        "in group \"y_not_test_group\" but the group has no write permission");

    check_explanation(
        REASON_OTHER_DENIED, ACCESS_EXECUTE,
        (PermissionResult){
            .reason = REASON_OTHER_DENIED,
            .source = PERMISSION_SOURCE_UNIX_OTHER,
            .entry_permissions = 4,
            .effective_permissions = 4,
        },
        0, false,
        "file is not marked executable for this user");

    check_explanation(
        REASON_STICKY_BIT, ACCESS_DELETE, (PermissionResult){0},
        1234, false,
        "the parent directory has the sticky bit; you own neither the entry nor the directory");

    check_explanation(
        REASON_OWNER_DENIED, ACCESS_READ,
        (PermissionResult){.reason = REASON_OWNER_DENIED},
        1234, true,
        "you own this directory but lack traverse permission");

    /* ACL denial where the entry itself lacks the bit (no mask involved). */
    check_explanation(
        REASON_ACL_DENIED, ACCESS_READ,
        (PermissionResult){
            .reason = REASON_ACL_DENIED,
            .source = PERMISSION_SOURCE_ACL_USER,
        },
        1234, false,
        "an ACL entry applies to you but does not grant read permission");

    /* ACL denial where the mask, not the entry, strips the requested bit:
       the entry grants rw- but the mask limits the effective rights. */
    check_explanation(
        REASON_ACL_DENIED, ACCESS_WRITE,
        (PermissionResult){
            .reason = REASON_ACL_DENIED,
            .source = PERMISSION_SOURCE_ACL_USER,
            .entry_permissions = 6, .effective_permissions = 4,
            .mask_permissions = 4, .mask_applied = true,
        },
        1234, false,
        "an ACL entry grants you write, but the ACL mask removes it");

    /* A mask is applied but the entry still lacks the bit: not a mask story. */
    check_explanation(
        REASON_ACL_DENIED, ACCESS_WRITE,
        (PermissionResult){
            .reason = REASON_ACL_DENIED,
            .source = PERMISSION_SOURCE_ACL_USER,
            .entry_permissions = 4, .effective_permissions = 4,
            .mask_permissions = 7, .mask_applied = true,
        },
        1234, false,
        "an ACL entry applies to you but does not grant write permission");

    /* A component y-not itself could not inspect (EACCES while resolving the
       path): the target user's verdict is undetermined, so the message is
       honest about the inspection failure rather than claiming a denial. */
    check_explanation(
        REASON_NOT_TRAVERSABLE, ACCESS_READ, (PermissionResult){0},
        0, false,
        "this path could not be inspected: y-not was denied access "
        "while resolving it; re-run it as root for a full verdict");

    /* A missing-group denial on a parent component concerns traversal, not
       the final requested operation. */
    {
        PathComponent components[3] = {0};
        components[0].path = "/";
        components[1].path = "/private";
        components[1].st.st_mode = S_IFDIR | 0700;
        components[1].checked_permission = (PermissionResult){
            .reason = REASON_GROUP_MISSING,
            .missing_group_gid = 1234,
            .missing_group_known = true,
        };
        components[1].checked_permission_known = true;
        components[2].path = "/private/target";
        AccessPath access_path = {.components = components, .count = 3};
        AccessResult result = {
            .allowed = false, .reason = REASON_GROUP_MISSING,
            .blocked_on_traversal = true, .blocked_path = components[1].path,
            .access_path = &access_path,
        };
        char actual[256];
        format_access_explanation(&result, ACCESS_WRITE, actual, sizeof(actual));
        CHECK(strcmp(actual,
                     "not in group \"y_not_test_group\" (which would allow traverse)") == 0);
    }

    CHECK(strcmp(access_operation_name(ACCESS_DELETE), "delete") == 0);

    /* The public formatter tolerates absent path metadata and small buffers. */
    {
        AccessResult result = {.allowed = false, .reason = REASON_NOT_FOUND};
        char actual[8];
        format_access_explanation(&result, ACCESS_READ, actual, sizeof(actual));
        CHECK(actual[sizeof(actual) - 1] == '\0');
        format_access_explanation(&result, ACCESS_READ, NULL, sizeof(actual));
        format_access_explanation(&result, ACCESS_READ, actual, 0);
        CHECK(strcmp(actual, "no such") == 0);
    }

    /* Defensive: a candidate count beyond the array capacity must be clamped,
       never read past the fixed array. Under ASan an overrun would abort. */
    {
        PermissionResult perm = {
            .reason = REASON_GROUP_MISSING,
            .source = PERMISSION_SOURCE_ACL_OTHER,
            .missing_group_gid = 1234,
            .missing_group_known = true,
            .candidate_group_count = Y_NOT_MAX_CANDIDATE_GROUPS + 5,
        };
        for (unsigned i = 0; i < Y_NOT_MAX_CANDIDATE_GROUPS; i++)
            perm.candidate_group_gids[i] = 1234;
        PathComponent components[2] = {0};
        components[0].path = "/";
        components[0].st.st_mode = S_IFDIR | 0755;
        components[1].path = "/target";
        components[1].st.st_mode = S_IFREG | 0640;
        components[1].checked_permission = perm;
        components[1].checked_permission_known = true;
        AccessPath access_path = {.components = components, .count = 2};
        AccessResult result = {
            .allowed = false, .reason = REASON_GROUP_MISSING,
            .blocked_path = components[1].path, .access_path = &access_path,
        };
        char actual[512];
        format_access_explanation(&result, ACCESS_READ, actual, sizeof(actual));
        CHECK(strncmp(actual, "not in any of the groups", 24) == 0);
    }

    return TEST_SUMMARY();
}
