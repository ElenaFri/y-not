#include "../include/access.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <pwd.h>
#include <string.h>
#include <unistd.h>

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

    /* access_result_free(NULL) must be silent */
    access_result_free(NULL);

    user_free(me);
    return TEST_SUMMARY();
}
