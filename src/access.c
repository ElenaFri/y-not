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
                return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
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

        /* Intermediate directories need traversal. Creating an entry in a
           target directory requires both search (x) and write (w); checking
           search first gives a useful, path-oriented explanation. */
        bool is_last = (i == ap->count - 1);
        bool blocked_on_traversal = false;
        PermissionResult check;
        if (!is_last)
            check = pr[ACCESS_EXECUTE];
        else if (operation == ACCESS_WRITE && S_ISDIR(comp->st.st_mode))
        {
            check = pr[ACCESS_EXECUTE];
            if (!check.allowed)
                blocked_on_traversal = true;
            else
                check = pr[ACCESS_WRITE];
        }
        else
            check = pr[operation];

        if (check.allowed && is_last)
        {
            AccessReason mount_reason = mount_restriction_reason(
                comp->mount_flags_known, comp->mount_read_only,
                comp->mount_noexec, &comp->st, operation);
            if (mount_reason != REASON_NONE)
                check = (PermissionResult){.allowed = false, .reason = mount_reason,
                                           .source = PERMISSION_SOURCE_MOUNT};
        }

        comp->checked_permission = check;
        comp->checked_permission_known = true;

        if (!check.allowed)
        {
            comp->denial_reason = check.reason;
            char *bp = strdup(comp->path);
            if (!bp)
            {
                path_free(ap);
                return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
            }
            return (AccessResult){.allowed = false,
                                  .blocked_path = bp,
                                  .reason = check.reason,
                                  .blocked_on_traversal = blocked_on_traversal,
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
