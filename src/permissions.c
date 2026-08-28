#include "permissions.h"

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op)
{
    (void)user;
    (void)st;
    (void)op;
    return (PermissionResult){.allowed = false, .reason = REASON_NONE};
}
