#include "access.h"

#include <stdlib.h>

AccessResult check_access(const User *user,
                          const char *path,
                          AccessOperation operation)
{
    (void)user;
    (void)path;
    (void)operation;
    return (AccessResult){
        .allowed = false,
        .blocked_path = NULL,
        .reason = REASON_NONE,
        .access_path = NULL,
    };
}

void access_result_free(AccessResult *result)
{
    if (!result)
        return;
    free(result->blocked_path);
    path_free(result->access_path);
}
