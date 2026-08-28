#include "user.h"

#include <stdlib.h>
#include <pwd.h>
#include <grp.h>

User *user_lookup(const char *username)
{
    (void)username;
    return NULL;
}

void user_free(User *user)
{
    if (!user)
        return;
    free(user->groups);
    free(user->name);
    free(user);
}
