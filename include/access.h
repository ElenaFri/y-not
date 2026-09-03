#pragma once

#include <stdbool.h>
#include "resolve/user.h"
#include "resolve/path.h" /* pulls in permissions.h */

typedef struct
{
    bool allowed;
    char *blocked_path; /* owned; freed by access_result_free() */
    AccessReason reason;
    AccessPath *access_path; /* full breakdown for the renderer */
} AccessResult;

AccessResult check_access(const User *user,
                          const char *path,
                          AccessOperation operation);
void access_result_free(AccessResult *result);
