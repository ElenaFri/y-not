#include "../include/access.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void check_directory_entry_creation(void)
{
    /* Directory entry creation requires both write and search permissions.
       Use a synthetic non-root user so this behaves the same in root CI. */
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/y_not_test_directory_write_XXXXXX", P_tmpdir);
    char *created = mkdtemp(dir);
    CHECK(created != NULL);
    if (!created)
        return;

    char target[sizeof(dir) + 16];
    snprintf(target, sizeof(target), "%s/target", dir);
    CHECK(chmod(dir, 0711) == 0); /* synthetic user can reach target */
    CHECK(mkdir(target, 0700) == 0);

    User alice = {.uid = 2000, .primary_gid = 2000,
                  .groups = NULL, .group_count = 0, .name = "y_not_test"};

    /* Read permission can list names even without search permission. */
    CHECK(chmod(target, 0644) == 0);
    AccessResult result = check_access(&alice, target, ACCESS_READ);
    CHECK(result.allowed);
    access_result_free(&result);

    /* Write without search is insufficient to create an entry. */
    CHECK(chmod(target, 0666) == 0);
    result = check_access(&alice, target, ACCESS_WRITE);
    CHECK(!result.allowed);
    CHECK(result.blocked_path != NULL && strcmp(result.blocked_path, target) == 0);
    CHECK(result.blocked_on_traversal);
    access_result_free(&result);

    /* Search without write is also insufficient. */
    CHECK(chmod(target, 0711) == 0);
    result = check_access(&alice, target, ACCESS_WRITE);
    CHECK(!result.allowed);
    CHECK(!result.blocked_on_traversal);
    access_result_free(&result);

    /* Both permissions allow creating directory entries. */
    CHECK(chmod(target, 0733) == 0);
    result = check_access(&alice, target, ACCESS_WRITE);
    CHECK(result.allowed);
    access_result_free(&result);

    CHECK(chmod(target, 0700) == 0);
    CHECK(rmdir(target) == 0);
    CHECK(chmod(dir, 0700) == 0);
    CHECK(rmdir(dir) == 0);
}

int main(void)
{
    const struct passwd *pw = getpwuid(getuid());
    if (!pw)
        return 0; /* skip if we can't resolve the current user */

    User *me = user_lookup(pw->pw_name);
    CHECK(me != NULL);
    if (!me)
        return TEST_SUMMARY();

    AccessResult r;

    /* /usr/bin/ls : readable and executable by everyone */
    r = check_access(me, "/usr/bin/ls", ACCESS_READ);
    CHECK(r.allowed);
    CHECK(r.reason == REASON_NONE);
    CHECK(r.access_path != NULL && r.access_path->count == 4);
    /* renderer data: every component must be traversable */
    if (r.access_path)
        for (size_t i = 0; i + 1 < r.access_path->count; i++)
            CHECK(r.access_path->components[i].can_execute);
    access_result_free(&r);

    r = check_access(me, "/usr/bin/ls", ACCESS_EXECUTE);
    CHECK(r.allowed);
    access_result_free(&r);

    /* non-existent path : blocked at the missing component */
    r = check_access(me, "/var/__y_not_no_such_path__", ACCESS_READ);
    CHECK(!r.allowed);
    CHECK(r.reason == REASON_NOT_FOUND);
    CHECK(r.blocked_path != NULL);
    access_result_free(&r);

    /* path_resolve() itself fails (NULL input) : denied, no access_path */
    r = check_access(me, NULL, ACCESS_READ);
    CHECK(!r.allowed);
    CHECK(r.reason == REASON_NOT_FOUND);
    CHECK(r.access_path == NULL);
    access_result_free(&r);

    /* a real permission denial (not a stat failure): /etc/passwd is
       world-readable but not world-writable, and a regular user is
       neither its owner nor in its group. Skip if running as root. */
    if (geteuid() != 0)
    {
        r = check_access(me, "/etc/passwd", ACCESS_WRITE);
        CHECK(!r.allowed);
        CHECK(r.reason != REASON_NONE && r.reason != REASON_NOT_FOUND);
        CHECK(r.blocked_path != NULL && strcmp(r.blocked_path, "/etc/passwd") == 0);
        access_result_free(&r);
    }

    check_directory_entry_creation();

    /* access_result_free(NULL) must be silent */
    access_result_free(NULL);

    user_free(me);
    return TEST_SUMMARY();
}
