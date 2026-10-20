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
        },
        5678, false,
        "not in group \"y_not_test_group\" (which would allow read)");

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
        REASON_OWNER_DENIED, ACCESS_READ,
        (PermissionResult){.reason = REASON_OWNER_DENIED},
        1234, true,
        "you own this directory but lack traverse permission");

    return TEST_SUMMARY();
}
