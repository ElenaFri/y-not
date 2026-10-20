#include "permissions/acl_eval.h"

#include <acl/libacl.h>

typedef struct
{
    bool r, w, x;
} AclMask;

static unsigned permset_bits(acl_permset_t ps)
{
    return (acl_get_perm(ps, ACL_READ) ? 4u : 0u) |
           (acl_get_perm(ps, ACL_WRITE) ? 2u : 0u) |
           (acl_get_perm(ps, ACL_EXECUTE) ? 1u : 0u);
}


static unsigned mask_bits(AclMask mask)
{
    return (mask.r ? 4u : 0u) | (mask.w ? 2u : 0u) | (mask.x ? 1u : 0u);
}

static unsigned operation_bit(AccessOperation op)
{
    return op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u;
}

static bool find_missing_acl_group(const User *user, const struct stat *st,
                                   AccessOperation op, acl_t acl, AclMask mask,
                                   gid_t *group_gid)
{
    unsigned needed = operation_bit(op);
    unsigned effective_mask = mask_bits(mask);
    acl_entry_t e;

    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e); rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_permset_t ps;
        if (acl_get_tag_type(e, &tag) != 0 || acl_get_permset(e, &ps) != 0)
            continue;
        if (!(permset_bits(ps) & effective_mask & needed))
            continue;

        if (tag == ACL_GROUP_OBJ && !user_in_group(user, st->st_gid))
        {
            *group_gid = st->st_gid;
            return true;
        }
        if (tag == ACL_GROUP)
        {
            gid_t *q = acl_get_qualifier(e);
            if (q)
            {
                gid_t candidate = *q;
                bool missing = !user_in_group(user, candidate);
                acl_free(q);
                if (missing)
                {
                    *group_gid = candidate;
                    return true;
                }
            }
        }
    }
    return false;
}

static PermissionResult result(bool allowed, AccessReason reason,
                               PermissionSource source, unsigned entry,
                               AclMask mask, bool masked)
{
    return (PermissionResult){
        .allowed = allowed,
        .reason = reason,
        .source = source,
        .entry_permissions = entry,
        .effective_permissions = masked ? entry & mask_bits(mask) : entry,
        .mask_permissions = mask_bits(mask),
        .mask_applied = masked,
    };
}

PermissionResult evaluate_acl_permissions(const User *user, const struct stat *st,
                                          AccessOperation op, acl_t acl)
{
    AclMask mask = {true, true, true};
    bool has_owner = false, has_user = false, has_group = false, has_other = false;
    unsigned owner = 0, named_user = 0, groups = 0, all_groups = 0, other = 0;
    acl_entry_t e;

    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e); rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_permset_t ps;
        if (acl_get_tag_type(e, &tag) != 0 || acl_get_permset(e, &ps) != 0)
            continue;
        unsigned bits = permset_bits(ps);
        switch (tag)
        {
        case ACL_USER_OBJ:
            has_owner = true;
            owner = bits;
            break;
        case ACL_USER:
        {
            uid_t *q = acl_get_qualifier(e);
            bool match = q && *q == user->uid;
            acl_free(q);
            if (match) { has_user = true; named_user = bits; }
            break;
        }
        case ACL_GROUP_OBJ:
            all_groups |= bits;
            if (user_in_group(user, st->st_gid))
            { has_group = true; groups |= bits; }
            break;
        case ACL_GROUP:
        {
            gid_t *q = acl_get_qualifier(e);
            all_groups |= bits;
            bool match = q && user_in_group(user, *q);
            acl_free(q);
            if (match) { has_group = true; groups |= bits; }
            break;
        }
        case ACL_MASK:
            mask.r = (bits & 4u) != 0;
            mask.w = (bits & 2u) != 0;
            mask.x = (bits & 1u) != 0;
            break;
        case ACL_OTHER:
            has_other = true;
            other = bits;
            break;
        default:
            break;
        }
    }

    if (user->uid == st->st_uid)
    {
        if (!has_owner) owner = (st->st_mode >> 6) & 7;
        bool allowed = (owner & (op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u)) != 0;
        return result(allowed, allowed ? REASON_NONE : REASON_OWNER_DENIED,
                      PERMISSION_SOURCE_ACL_OWNER, owner, mask, false);
    }
    if (has_user)
    {
        bool allowed = (named_user & mask_bits(mask) & (op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u)) != 0;
        return result(allowed, allowed ? REASON_NONE : REASON_ACL_DENIED,
                      PERMISSION_SOURCE_ACL_USER, named_user, mask, true);
    }
    if (has_group)
    {
        bool allowed = (groups & mask_bits(mask) & (op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u)) != 0;
        return result(allowed, allowed ? REASON_NONE : REASON_ACL_DENIED,
                      PERMISSION_SOURCE_ACL_GROUP, groups, mask, true);
    }
    bool allowed = has_other && (other & (op == ACCESS_READ ? 4u : op == ACCESS_WRITE ? 2u : 1u));
    if (allowed)
        return result(true, REASON_NONE, PERMISSION_SOURCE_ACL_OTHER, other, mask, false);

    /* Report group_missing only when the matching ACL group entries would
       grant this operation after applying the ACL mask. */
    AccessReason reason = (all_groups & mask_bits(mask) & operation_bit(op))
                              ? REASON_GROUP_MISSING : REASON_OTHER_DENIED;
    PermissionResult denied = result(false, reason, PERMISSION_SOURCE_ACL_OTHER,
                                     other, mask, false);
    if (reason == REASON_GROUP_MISSING)
        denied.missing_group_known = find_missing_acl_group(
            user, st, op, acl, mask, &denied.missing_group_gid);
    return denied;
}
