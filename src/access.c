#include "access.h"

#include <stdlib.h>
#include <string.h>

AccessResult check_access(const User *user,
                          const char *path,
                          AccessOperation operation)
{
    AccessPath *ap = path_resolve(path);
    if (!ap)
        return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};

    for (size_t i = 0; i < ap->count; i++)
    {
        PathComponent *comp = &ap->components[i];

        if (comp->denial_reason != REASON_NONE)
        {
            char *bp = strdup(comp->path);
            if (!bp)
            {
                path_free(ap);
                break;
            }
            return (AccessResult){.allowed = false,
                                  .blocked_path = bp,
                                  .reason = comp->denial_reason,
                                  .access_path = ap};
        }

        /* Evaluate all three operations: renderer needs the full picture */
        PermissionResult pr[3];
        pr[ACCESS_READ] = evaluate_permissions(user, &comp->st, ACCESS_READ, comp->acl);
        pr[ACCESS_WRITE] = evaluate_permissions(user, &comp->st, ACCESS_WRITE, comp->acl);
        pr[ACCESS_EXECUTE] = evaluate_permissions(user, &comp->st, ACCESS_EXECUTE, comp->acl);

        comp->can_read = pr[ACCESS_READ].allowed;
        comp->can_write = pr[ACCESS_WRITE].allowed;
        comp->can_execute = pr[ACCESS_EXECUTE].allowed;

        /* Intermediate directories need traversal; target needs the requested op */
        bool is_last = (i == ap->count - 1);
        PermissionResult check = pr[is_last ? operation : ACCESS_EXECUTE];

        if (!check.allowed)
        {
            comp->denial_reason = check.reason;
            char *bp = strdup(comp->path);
            if (!bp)
            {
                path_free(ap);
                break;
            }
            return (AccessResult){.allowed = false,
                                  .blocked_path = bp,
                                  .reason = check.reason,
                                  .access_path = ap};
        }
    }

    return (AccessResult){.allowed = true, .reason = REASON_NONE, .access_path = ap};
}

void access_result_free(AccessResult *result)
{
    if (!result)
        return;
    free(result->blocked_path);
    path_free(result->access_path);
}
