#include "permissions/permissions.h"

#include "permissions/acl_eval.h"
#include "permissions/capabilities.h"
#include "permissions/mode_bits.h"

static unsigned mode_permission_bits(mode_t mode, int shift)
{
    return (unsigned)((mode >> shift) & 7);
}

static unsigned operation_bit(AccessOperation op)
{
    return op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u;
}

static PermissionResult permission_result(bool allowed, AccessReason reason,
                                          PermissionSource source,
                                          unsigned entry_permissions,
                                          unsigned mask_permissions,
                                          bool mask_applied)
{
    unsigned effective = mask_applied ? entry_permissions & mask_permissions
                                      : entry_permissions;
    return (PermissionResult){
        .allowed = allowed, .reason = reason, .source = source,
        .entry_permissions = entry_permissions,
        .effective_permissions = effective,
        .mask_permissions = mask_permissions, .mask_applied = mask_applied,
    };
}

PermissionResult evaluate_permissions(const User *user, const struct stat *st,
                                      AccessOperation op, acl_t acl)
{
    mode_t mode = st->st_mode;
    unsigned bit = operation_bit(op);

    if (user->uid == 0)
    {
        bool ok = op != ACCESS_EXECUTE || !S_ISREG(mode) ||
                  (mode & (S_IXUSR | S_IXGRP | S_IXOTH));
        return permission_result(ok, ok ? REASON_NONE : REASON_OWNER_DENIED,
                                 PERMISSION_SOURCE_DAC_OVERRIDE, 7, 7, false);
    }
    if (user_has_dac_override(user))
    {
        bool ok = op != ACCESS_EXECUTE || !S_ISREG(mode) ||
                  (mode & (S_IXUSR | S_IXGRP | S_IXOTH));
        return permission_result(ok, ok ? REASON_NONE : REASON_OWNER_DENIED,
                                 PERMISSION_SOURCE_CAP_DAC_OVERRIDE, 7, 7, false);
    }
    if (user_has_dac_read_search(user) &&
        (op == ACCESS_READ || (op == ACCESS_EXECUTE && S_ISDIR(mode))))
        return permission_result(true, REASON_NONE,
                                 PERMISSION_SOURCE_CAP_DAC_READ_SEARCH, 7, 7, false);

    if (acl)
        return evaluate_acl_permissions(user, st, op, acl);

    if (user->uid == st->st_uid)
    {
        unsigned bits = mode_permission_bits(mode, 6);
        bool ok = (bits & bit) != 0;
        return permission_result(ok, ok ? REASON_NONE : REASON_OWNER_DENIED,
                                 PERMISSION_SOURCE_UNIX_OWNER, bits, 7, false);
    }
    if (user_in_group(user, st->st_gid))
    {
        unsigned bits = mode_permission_bits(mode, 3);
        bool ok = (bits & bit) != 0;
        return permission_result(ok, ok ? REASON_NONE : REASON_GROUP_DENIED,
                                 PERMISSION_SOURCE_UNIX_GROUP, bits, 7, false);
    }
    unsigned other = mode_permission_bits(mode, 0);
    if (other & bit)
        return permission_result(true, REASON_NONE, PERMISSION_SOURCE_UNIX_OTHER,
                                 other, 7, false);
    unsigned group = mode_permission_bits(mode, 3);
    AccessReason reason = (group & bit) ? REASON_GROUP_MISSING : REASON_OTHER_DENIED;
    return permission_result(false, reason, PERMISSION_SOURCE_UNIX_OTHER,
                             other, 7, false);
}

AccessReason mount_restriction_reason(bool flags_known, bool read_only,
                                      bool noexec, const struct stat *st,
                                      AccessOperation op)
{
    if (!flags_known || !st)
        return REASON_NONE;
    if (op == ACCESS_WRITE && read_only)
        return REASON_MOUNT_READ_ONLY;
    if (op == ACCESS_EXECUTE && S_ISREG(st->st_mode) && noexec)
        return REASON_MOUNT_NOEXEC;
    return REASON_NONE;
}
