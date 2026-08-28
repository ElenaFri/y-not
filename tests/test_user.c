#include "../include/user.h"
#include "testlib.h"

#include <string.h>
#include <pwd.h>
#include <unistd.h>

int main(void)
{
    /* user_free(NULL) doit être silencieux */
    user_free(NULL);

    CHECK(user_lookup("__y_not_no_such_user__") == NULL);

    /* root est toujours présent sur Linux */
    User *root = user_lookup("root");
    CHECK(root != NULL);
    if (root)
    {
        CHECK(root->uid == 0);
        CHECK(root->primary_gid == 0);
        CHECK(strcmp(root->name, "root") == 0);
        CHECK(root->group_count >= 1);

        /* getgrouplist inclut toujours le gid primaire */
        int found = 0;
        for (size_t i = 0; i < root->group_count; i++)
            if (root->groups[i] == root->primary_gid)
            {
                found = 1;
                break;
            }
        CHECK(found);
        user_free(root);
    }

    /* utilisateur courant */
    struct passwd *pw = getpwuid(getuid());
    if (pw)
    {
        User *me = user_lookup(pw->pw_name);
        CHECK(me != NULL);
        if (me)
        {
            CHECK(me->uid == getuid());
            CHECK(me->group_count >= 1);
            user_free(me);
        }
    }

    return TEST_SUMMARY();
}
