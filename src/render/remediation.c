#include "render/remediation.h"
#include "render/explanation.h"

#include <grp.h>
#include <stdio.h>
#include <string.h>

static const char *gid_to_name(gid_t gid, char *buffer, size_t buffer_size)
{
    const struct group *group = getgrgid(gid);
    if (group)
        return group->gr_name;
    snprintf(buffer, buffer_size, "%u", (unsigned)gid);
    return buffer;
}

/* rwx bitset -> only the letters that are set, e.g. 5 -> "rx", 0 -> "-".
   setfacl accepts this compact form for a permset. */
static void perms_letters(unsigned bits, char out[4])
{
    size_t n = 0;
    if (bits & 4u)
        out[n++] = 'r';
    if (bits & 2u)
        out[n++] = 'w';
    if (bits & 1u)
        out[n++] = 'x';
    if (n == 0)
        out[n++] = '-';
    out[n] = '\0';
}

static char need_perm_char(AccessOperation op, bool traversal)
{
    if (traversal)
        return 'x'; /* a parent (or a final directory being written) needs search */
    return op == ACCESS_READ ? 'r' : (op == ACCESS_WRITE || op == ACCESS_DELETE) ? 'w' : 'x';
}

static bool blocked_is_last_component(const AccessResult *result)
{
    if (!result->access_path || !result->blocked_path ||
        result->access_path->count == 0)
        return true;
    const char *last = result->access_path
                           ->components[result->access_path->count - 1]
                           .path;
    return last && strcmp(last, result->blocked_path) == 0;
}

bool format_remediation(const AccessResult *result, AccessOperation op,
                        const char *user_name, char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
        return false;
    buffer[0] = '\0';
    if (!result || result->allowed)
        return false;

    const PathComponent *blocked = access_blocked_component(result);
    const char *path = result->blocked_path ? result->blocked_path : "PATH";
    const char *name = user_name ? user_name : "USER";

    bool traversal = (op != ACCESS_DELETE && !blocked_is_last_component(result)) ||
                     result->blocked_on_traversal;
    char need = need_perm_char(op, traversal);
    unsigned need_bit = need == 'r' ? 4u : need == 'w' ? 2u : 1u;

    const char *object = (blocked && S_ISDIR(blocked->st.st_mode))
                             ? "directory"
                             : "file";

    /* Changing a file's mode or ACL requires being its owner or root. Only
       REASON_OWNER_DENIED means the requesting user owns the object (an owner
       denied through an ACL owner entry also maps to it), so that fix runs as
       the user; every other denial is a non-owner and the command is prefixed
       with sudo, without which it would fail with EPERM. */
    switch (result->reason)
    {
    case REASON_OWNER_DENIED:
        snprintf(buffer, buffer_size,
                 "add the missing permission: chmod u+%c %s", need, path);
        return true;
    case REASON_GROUP_DENIED:
        snprintf(buffer, buffer_size,
                 "add the permission for the %s's group: sudo chmod g+%c %s",
                 object, need, path);
        return true;
    case REASON_GROUP_MISSING:
    {
        gid_t gid = blocked ? blocked->st.st_gid : 0;
        if (blocked && blocked->checked_permission_known &&
            blocked->checked_permission.missing_group_known)
            gid = blocked->checked_permission.missing_group_gid;
        char gbuf[32];
        const char *gname = gid_to_name(gid, gbuf, sizeof(gbuf));
        snprintf(buffer, buffer_size,
                 "add %s to a group that grants it: sudo usermod -aG %s %s, "
                 "then log in again",
                 name, gname, name);
        return true;
    }
    case REASON_OTHER_DENIED:
        snprintf(buffer, buffer_size,
                 "grant only this user via ACL: sudo setfacl -m u:%s:%c %s",
                 name, need, path);
        return true;
    case REASON_ACL_DENIED:
    {
        const PermissionResult *perm =
            blocked ? &blocked->checked_permission : NULL;
        bool mask_blocks = perm && blocked->checked_permission_known &&
                           perm->mask_applied &&
                           (perm->entry_permissions & need_bit) &&
                           !(perm->effective_permissions & need_bit);
        if (mask_blocks)
        {
            char mask[4];
            perms_letters(perm->mask_permissions | need_bit, mask);
            snprintf(buffer, buffer_size,
                     "widen the ACL mask: sudo setfacl -m m::%s %s", mask, path);
        }
        else
        {
            unsigned entry = perm ? perm->entry_permissions : 0u;
            char grant[4];
            perms_letters(entry | need_bit, grant);
            snprintf(buffer, buffer_size,
                     "extend this user's ACL entry: sudo setfacl -m u:%s:%s %s",
                     name, grant, path);
        }
        return true;
    }
    case REASON_MOUNT_READ_ONLY:
        snprintf(buffer, buffer_size,
                 "this is a read-only mount, not a permission; "
                 "remount read-write to allow writes");
        return true;
    case REASON_MOUNT_NOEXEC:
        snprintf(buffer, buffer_size,
                 "this is a noexec mount, not a permission; "
                 "remount without noexec to allow execution");
        return true;
    case REASON_STICKY_BIT:
        snprintf(buffer, buffer_size,
                 "take ownership of the entry so the sticky directory lets you "
                 "remove it: sudo chown %s %s",
                 name, path);
        return true;
    case REASON_DELETE_ROOT:
        snprintf(buffer, buffer_size,
                 "the filesystem root cannot be removed; this is a kernel rule, "
                 "not a permission");
        return true;
    case REASON_DELETE_SPECIAL:
        snprintf(buffer, buffer_size,
                 "the . and .. entries cannot be removed; this is a kernel rule, "
                 "not a permission");
        return true;
    default:
        /* NOT_TRAVERSABLE, NOT_FOUND, BROKEN_SYMLINK, SYMLINK_LOOP: no
           permission change would make this access succeed. For
           NOT_TRAVERSABLE y-not could not even inspect the component, so it
           cannot honestly name a fix; the explanation says to re-run as root. */
        buffer[0] = '\0';
        return false;
    }
}
