#include "permissions/permissions.h"

#include "permissions/acl_eval.h"
#include "permissions/capabilities.h"
#include "permissions/mode_bits.h"

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op,
                                      acl_t acl)
{
    mode_t mode = st->st_mode;

    /* root bypasses checks; exception: execute requires at least one x bit */
    if (user->uid == 0)
    {
        bool ok = op != ACCESS_EXECUTE || (mode & (S_IXUSR | S_IXGRP | S_IXOTH));
        return (PermissionResult){.allowed = ok,
                                  .reason = ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

    /* CAP_DAC_OVERRIDE (via pam_cap): bypasses everything, same as root. */
    if (user_has_dac_override(user))
    {
        bool ok = op != ACCESS_EXECUTE || (mode & (S_IXUSR | S_IXGRP | S_IXOTH));
        return (PermissionResult){.allowed = ok,
                                  .reason = ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

    /* CAP_DAC_READ_SEARCH: bypasses read and directory traversal only -
       write, and execute on a regular file, still go through normal checks. */
    if (user_has_dac_read_search(user))
    {
        if (op == ACCESS_READ || (op == ACCESS_EXECUTE && S_ISDIR(mode)))
            return (PermissionResult){.allowed = true, .reason = REASON_NONE};
    }

    if (acl)
        return evaluate_acl_permissions(user, st, op, acl);

    /* Standard Unix evaluation (no extended ACL). */
    if (user->uid == st->st_uid)
    {
        bool ok = class_allows(mode, op, 6);
        return (PermissionResult){.allowed = ok,
                                  .reason = ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

    if (user_in_group(user, st->st_gid))
    {
        bool ok = class_allows(mode, op, 3);
        return (PermissionResult){.allowed = ok,
                                  .reason = ok ? REASON_NONE : REASON_GROUP_DENIED};
    }

    if (class_allows(mode, op, 0))
        return (PermissionResult){.allowed = true, .reason = REASON_NONE};

    AccessReason reason = class_allows(mode, op, 3) ? REASON_GROUP_MISSING
                                                    : REASON_OTHER_DENIED;
    return (PermissionResult){.allowed = false, .reason = reason};
}
