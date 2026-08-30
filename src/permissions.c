#include "permissions.h"

#include <acl/libacl.h>

/* Shift mode bits to the "other" position for uniform comparison. */
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
    default:
        return false;
    }
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

/* ---- ACL helpers ---- */

typedef struct
{
    bool r, w, x;
} AclMask;

static AclMask extract_mask(acl_t acl)
{
    AclMask m = {true, true, true}; /* no mask entry = all allowed */
    acl_entry_t e;
    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
         rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_get_tag_type(e, &tag);
        if (tag == ACL_MASK)
        {
            acl_permset_t ps;
            acl_get_permset(e, &ps);
            m.r = (bool)acl_get_perm(ps, ACL_READ);
            m.w = (bool)acl_get_perm(ps, ACL_WRITE);
            m.x = (bool)acl_get_perm(ps, ACL_EXECUTE);
            break;
        }
    }
    return m;
}

/* Permset allows op, AND mask applied. */
static bool perm_allows(acl_permset_t ps, AclMask mask, AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:
        return (bool)acl_get_perm(ps, ACL_READ) && mask.r;
    case ACCESS_WRITE:
        return (bool)acl_get_perm(ps, ACL_WRITE) && mask.w;
    case ACCESS_EXECUTE:
        return (bool)acl_get_perm(ps, ACL_EXECUTE) && mask.x;
    default:
        return false;
    }
}

/* Permset allows op, no mask (used for USER_OBJ and OTHER). */
static bool raw_allows(acl_permset_t ps, AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:
        return (bool)acl_get_perm(ps, ACL_READ);
    case ACCESS_WRITE:
        return (bool)acl_get_perm(ps, ACL_WRITE);
    case ACCESS_EXECUTE:
        return (bool)acl_get_perm(ps, ACL_EXECUTE);
    default:
        return false;
    }
}

/*
 * POSIX ACL evaluation algorithm:
 *   1. ACL_USER_OBJ  (owner)   → decisive, no mask
 *   2. ACL_USER      (uid)     → decisive if matched, mask applied
 *   3. ACL_GROUP_OBJ / ACL_GROUP (any group) → collective, mask applied
 *   4. ACL_OTHER                → decisive, no mask
 */
static PermissionResult evaluate_acl(const User *user, const struct stat *st,
                                     AccessOperation op, acl_t acl)
{
    AclMask mask = extract_mask(acl);
    acl_entry_t e;

    /* Step 1: owner */
    if (user->uid == st->st_uid)
    {
        for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
             rv == 1;
             rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
        {
            acl_tag_t tag;
            acl_get_tag_type(e, &tag);
            if (tag == ACL_USER_OBJ)
            {
                acl_permset_t ps;
                acl_get_permset(e, &ps);
                bool ok = raw_allows(ps, op);
                return (PermissionResult){ok, ok ? REASON_NONE : REASON_OWNER_DENIED};
            }
        }
        /* Valid ACL always has USER_OBJ; fall back to mode bits if not found. */
        bool ok = class_allows(st->st_mode, op, 6);
        return (PermissionResult){ok, ok ? REASON_NONE : REASON_OWNER_DENIED};
    }

    /* Step 2: named user (decisive on match) */
    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
         rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_get_tag_type(e, &tag);
        if (tag != ACL_USER)
            continue;
        uid_t *q = acl_get_qualifier(e);
        bool match = (*q == user->uid);
        acl_free(q);
        if (match)
        {
            acl_permset_t ps;
            acl_get_permset(e, &ps);
            bool ok = perm_allows(ps, mask, op);
            return (PermissionResult){ok, ok ? REASON_NONE : REASON_ACL_DENIED};
        }
    }

    /* Step 3: group entries (collective result) */
    bool grp_match = false, grp_grant = false;
    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
         rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_get_tag_type(e, &tag);
        if (tag == ACL_GROUP_OBJ && user_in_group(user, st->st_gid))
        {
            grp_match = true;
            acl_permset_t ps;
            acl_get_permset(e, &ps);
            if (perm_allows(ps, mask, op))
                grp_grant = true;
        }
        if (tag == ACL_GROUP)
        {
            gid_t *q = acl_get_qualifier(e);
            bool in_grp = user_in_group(user, *q);
            acl_free(q);
            if (in_grp)
            {
                grp_match = true;
                acl_permset_t ps;
                acl_get_permset(e, &ps);
                if (perm_allows(ps, mask, op))
                    grp_grant = true;
            }
        }
    }
    if (grp_match)
        return (PermissionResult){grp_grant, grp_grant ? REASON_NONE : REASON_ACL_DENIED};

    /* Step 4: other (decisive, no mask) */
    for (int rv = acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
         rv == 1;
         rv = acl_get_entry(acl, ACL_NEXT_ENTRY, &e))
    {
        acl_tag_t tag;
        acl_get_tag_type(e, &tag);
        if (tag == ACL_OTHER)
        {
            acl_permset_t ps;
            acl_get_permset(e, &ps);
            bool ok = raw_allows(ps, op);
            AccessReason r = ok ? REASON_NONE
                                : (class_allows(st->st_mode, op, 3) ? REASON_GROUP_MISSING : REASON_OTHER_DENIED);
            return (PermissionResult){ok, r};
        }
    }

    return (PermissionResult){false, REASON_OTHER_DENIED};
}

/* ---- Public interface ---- */

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

    if (acl)
        return evaluate_acl(user, st, op, acl);

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
