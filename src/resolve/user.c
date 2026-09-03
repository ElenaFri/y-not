#include "resolve/user.h"

#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

User *user_lookup(const char *username)
{
    struct passwd *pw = getpwnam(username);
    if (!pw)
        return NULL;

    User *user = malloc(sizeof(*user));
    if (!user)
        return NULL;

    user->name = strdup(pw->pw_name);
    if (!user->name)
        goto err_user;

    user->uid = pw->pw_uid;
    user->primary_gid = pw->pw_gid;

    int ngroups = 64;
    gid_t *groups = malloc((size_t)ngroups * sizeof(gid_t));
    if (!groups)
        goto err_name;

    while (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) == -1)
    {
        gid_t *tmp = realloc(groups, (size_t)ngroups * sizeof(gid_t));
        if (!tmp)
            goto err_groups;
        groups = tmp;
    }

    user->groups = groups;
    user->group_count = (size_t)ngroups;
    return user;

err_groups:
    free(groups);
err_name:
    free(user->name);
err_user:
    free(user);
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
