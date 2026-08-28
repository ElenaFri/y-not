#include "permissions.h"

/* Shift mode bits to the 'other' position for uniform comparison */
static bool class_allows(mode_t mode, AccessOperation op, int shift)
{
    mode_t m = mode >> shift;
    switch (op)
    {
    case ACCESS_READ:
        return m & S_IROTH;
    case ACCESS_WRITE:
        return m & S_IWOTH;
    case ACCESS_EXECUTE:
        return m & S_IXOTH;
    }
    return false;
}

static bool user_in_group(const User *user, gid_t gid)
{
    if (user->primary_gid == gid)
        return true;
    for (size_t i = 0; i < user->group_count; i++)
        if (user->groups[i] == gid)
            return true;
    return false;
}

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op)
{
    mode_t mode = st->st_mode;

    /* root bypasses checks; exception: execute requires at least one x bit */
    if (user->uid == 0)
    {
        bool ok = op != ACCESS_EXECUTE || (mode & (S_IXUSR | S_IXGRP | S_IXOTH));
        return (PermissionResult){.allowed = ok,
                                  .reason = ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

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

    /* Denied as other — was the group the missing key? */
    AccessReason reason = class_allows(mode, op, 3) ? REASON_GROUP_MISSING
                                                    : REASON_OTHER_DENIED;
    return (PermissionResult){.allowed = false, .reason = reason};
}
