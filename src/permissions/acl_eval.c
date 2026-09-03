#include "permissions/acl_eval.h"

#include <acl/libacl.h>

typedef struct
{
    bool r, w, x;
} AclMask;

static bool mask_allows(AclMask mask, AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:    return mask.r;
    case ACCESS_WRITE:   return mask.w;
    case ACCESS_EXECUTE: return mask.x;
    default:             return false;
    }
}

static bool permset_allows(acl_permset_t ps, AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:    return (bool)acl_get_perm(ps, ACL_READ);
    case ACCESS_WRITE:   return (bool)acl_get_perm(ps, ACL_WRITE);
    case ACCESS_EXECUTE: return (bool)acl_get_perm(ps, ACL_EXECUTE);
    default:             return false;
    }
}

/*
 * POSIX ACL evaluation: a single pass collects what each entry class says,
 * then one decision applies the priority owner > named user > group(s) >
 * other. The mask is applied once at the end rather than per-entry - the
 * two are equivalent since it's a single constant factor common to every
 * named-user/group check ((A1 & M) | (A2 & M) = M & (A1 | A2)), and
 * deferring it means entry order (mask before or after group entries)
 * cannot matter.
 */
PermissionResult evaluate_acl_permissions(const User *user, const struct stat *st,
                                          AccessOperation op, acl_t acl)
{
    AclMask mask = {true, true, true}; /* no ACL_MASK entry = unrestricted */
    bool has_owner = false, owner_allows = false;
    bool has_user = false, user_allows = false;   /* named entry for this uid */
    bool has_group = false, group_allows = false;  /* any matching group entry */
    bool has_other = false, other_allows = false;

    acl_entry_t e;
    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
         rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_get_tag_type(e, &tag);
        acl_permset_t ps;
        acl_get_permset(e, &ps);

        switch (tag)
        {
        case ACL_USER_OBJ:
            has_owner = true;
            owner_allows = permset_allows(ps, op);
            break;

        case ACL_USER:
        {
            uid_t *q = acl_get_qualifier(e);
            bool match = q && *q == user->uid;
            acl_free(q);
            if (match)
            {
                has_user = true;
                user_allows = permset_allows(ps, op);
            }
            break;
        }

        case ACL_GROUP_OBJ:
            if (user_in_group(user, st->st_gid))
            {
                has_group = true;
                if (permset_allows(ps, op))
                    group_allows = true;
            }
            break;

        case ACL_GROUP:
        {
            gid_t *q = acl_get_qualifier(e);
            bool in_grp = q && user_in_group(user, *q);
            acl_free(q);
            if (in_grp)
            {
                has_group = true;
                if (permset_allows(ps, op))
                    group_allows = true;
            }
            break;
        }

        case ACL_MASK:
            mask.r = (bool)acl_get_perm(ps, ACL_READ);
            mask.w = (bool)acl_get_perm(ps, ACL_WRITE);
            mask.x = (bool)acl_get_perm(ps, ACL_EXECUTE);
            break;

        case ACL_OTHER:
            has_other = true;
            other_allows = permset_allows(ps, op);
            break;

        default:
            break;
        }
    }

    /* Step 1: owner - decisive, no mask */
    if (user->uid == st->st_uid)
    {
        /* Valid ACLs always have USER_OBJ; fall back to mode bits if not found. */
        bool ok = has_owner ? owner_allows : class_allows(st->st_mode, op, 6);
        return (PermissionResult){ok, ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

    /* Step 2: named user - decisive on match, mask applied */
    if (has_user)
    {
        bool ok = user_allows && mask_allows(mask, op);
        return (PermissionResult){ok, ok ? REASON_NONE : REASON_ACL_DENIED};
    }

    /* Step 3: group(s) - collective result, mask applied */
    if (has_group)
    {
        bool ok = group_allows && mask_allows(mask, op);
        return (PermissionResult){ok, ok ? REASON_NONE : REASON_ACL_DENIED};
    }

    /* Step 4: other - decisive, no mask */
    bool ok = has_other && other_allows;
    AccessReason reason = ok ? REASON_NONE
                             : (class_allows(st->st_mode, op, 3) ? REASON_GROUP_MISSING
                                                                  : REASON_OTHER_DENIED);
    return (PermissionResult){ok, reason};
}
