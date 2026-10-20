#include "../include/permissions/permissions.h"
#include "testlib.h"

#include <sys/stat.h>

static const uid_t DAC_OVERRIDE_UID = 9000;
static const uid_t DAC_READ_SEARCH_UID = 9001;

bool user_has_dac_override(const User *user)
{
    return user->uid == DAC_OVERRIDE_UID;
}

bool user_has_dac_read_search(const User *user)
{
    return user->uid == DAC_READ_SEARCH_UID;
}

static User make_user(uid_t uid)
{
    return (User){.uid = uid, .primary_gid = 900, .groups = NULL,
                  .group_count = 0, .name = "cap-test"};
}

int main(void)
{
    User override = make_user(DAC_OVERRIDE_UID);
    User read_search = make_user(DAC_READ_SEARCH_UID);
    User ordinary = make_user(9002);
    struct stat file = {.st_uid = 1000, .st_gid = 100,
                        .st_mode = S_IFREG | 0000};
    struct stat executable = file;
    executable.st_mode = S_IFREG | 0010;
    struct stat directory = {.st_uid = 1000, .st_gid = 100,
                             .st_mode = S_IFDIR | 0000};

    PermissionResult result = evaluate_permissions(&override, &file, ACCESS_READ, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_OVERRIDE);
    result = evaluate_permissions(&override, &file, ACCESS_WRITE, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_OVERRIDE);
    result = evaluate_permissions(&override, &file, ACCESS_EXECUTE, NULL);
    CHECK(!result.allowed && result.reason == REASON_OWNER_DENIED);
    result = evaluate_permissions(&override, &executable, ACCESS_EXECUTE, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_OVERRIDE);
    result = evaluate_permissions(&override, &directory, ACCESS_EXECUTE, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_OVERRIDE);

    result = evaluate_permissions(&read_search, &file, ACCESS_READ, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_READ_SEARCH);
    result = evaluate_permissions(&read_search, &directory, ACCESS_EXECUTE, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_READ_SEARCH);
    result = evaluate_permissions(&read_search, &directory, ACCESS_READ, NULL);
    CHECK(result.allowed && result.source == PERMISSION_SOURCE_CAP_DAC_READ_SEARCH);
    result = evaluate_permissions(&read_search, &file, ACCESS_WRITE, NULL);
    CHECK(!result.allowed && result.reason == REASON_OTHER_DENIED);
    result = evaluate_permissions(&read_search, &file, ACCESS_EXECUTE, NULL);
    CHECK(!result.allowed && result.reason == REASON_OTHER_DENIED);

    result = evaluate_permissions(&ordinary, &file, ACCESS_READ, NULL);
    CHECK(!result.allowed && result.source == PERMISSION_SOURCE_UNIX_OTHER);
    return TEST_SUMMARY();
}
