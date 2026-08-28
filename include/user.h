#pragma once

#include <sys/types.h>
#include <stddef.h>

typedef struct
{
    uid_t uid;
    gid_t primary_gid;
    gid_t *groups;
    size_t group_count;
    char *name;
} User;

/* Returns NULL if the user does not exist or on allocation failure. */
User *user_lookup(const char *username);
void user_free(User *user);
