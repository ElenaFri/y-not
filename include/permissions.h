#pragma once

#include <sys/stat.h>
#include <stdbool.h>
#include "user.h"

typedef enum
{
    ACCESS_READ,
    ACCESS_WRITE,
    ACCESS_EXECUTE,
} AccessOperation;

typedef enum
{
    REASON_NONE = 0,
    REASON_OWNER_DENIED,
    REASON_GROUP_DENIED,  /* in group, but group bits deny */
    REASON_GROUP_MISSING, /* not in group; group bits would allow */
    REASON_OTHER_DENIED,
    REASON_NOT_TRAVERSABLE,
    REASON_NOT_FOUND,
} AccessReason;

typedef struct
{
    bool allowed;
    AccessReason reason;
} PermissionResult;

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op);
