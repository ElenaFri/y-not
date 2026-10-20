#include "../include/resolve/user.h"
#include "testlib.h"

#include <pwd.h>
#include <string.h>

static struct passwd wide_account = {
    .pw_name = "wide",
    .pw_uid = 4100,
    .pw_gid = 410,
};
static struct passwd small_account = {
    .pw_name = "small",
    .pw_uid = 4200,
    .pw_gid = 420,
};
static unsigned wide_group_calls;
static unsigned small_group_calls;

struct passwd *getpwnam(const char *name)
{
    if (strcmp(name, wide_account.pw_name) == 0)
        return &wide_account;
    if (strcmp(name, small_account.pw_name) == 0)
        return &small_account;
    return NULL;
}

int getgrouplist(const char *user, gid_t primary, gid_t *groups, int *count)
{
    if (strcmp(user, "small") == 0)
    {
        small_group_calls++;
        if (*count < 2)
        {
            *count = 2;
            return -1;
        }
        groups[0] = primary;
        groups[1] = 421;
        *count = 2;
        return 2;
    }

    wide_group_calls++;
    if (*count < 70)
    {
        *count = 70;
        return -1;
    }
    if (*count < 130)
    {
        *count = 130;
        return -1;
    }
    for (int i = 0; i < 130; i++)
        groups[i] = (gid_t)(500 + i);
    groups[0] = primary;
    *count = 130;
    return 130;
}

int main(void)
{
    CHECK(user_lookup("missing") == NULL);

    User *small = user_lookup("small");
    CHECK(small != NULL);
    if (small)
    {
        CHECK(small->uid == 4200 && small->primary_gid == 420);
        CHECK(small->group_count == 2);
        CHECK(small->groups[0] == 420 && small->groups[1] == 421);
        CHECK(small_group_calls == 1);
        user_free(small);
    }

    User *wide = user_lookup("wide");
    CHECK(wide != NULL);
    if (wide)
    {
        CHECK(wide->group_count == 130);
        CHECK(wide->groups[0] == 410);
        CHECK(wide->groups[129] == 629);
        CHECK(wide_group_calls == 3); /* retries after both size increases */
        user_free(wide);
    }

    user_free(NULL);
    return TEST_SUMMARY();
}
