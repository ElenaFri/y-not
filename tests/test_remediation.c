#include "../include/render/remediation.h"
#include "testlib.h"

#include <grp.h>
#include <string.h>

/* gid 10 resolves to a name; any other gid falls back to its number. */
static struct group mock_group = {.gr_name = "wheel", .gr_gid = 10};

struct group *getgrgid(gid_t gid)
{
    return gid == mock_group.gr_gid ? &mock_group : NULL;
}

/* Build a two-component path (/ and /target) blocked at the target and return
   the remediation string for `op`. target_mode sets the type/mode bits. */
static bool remediation_for(AccessReason reason, AccessOperation op,
                            PermissionResult perm, mode_t target_mode,
                            bool blocked_on_traversal, char *out, size_t out_size)
{
    PathComponent components[2] = {0};
    components[0].path = "/";
    components[0].st.st_mode = S_IFDIR | 0755;
    components[1].path = "/target";
    components[1].st.st_mode = target_mode;
    components[1].st.st_gid = perm.missing_group_known ? 0 : mock_group.gr_gid;
    components[1].checked_permission = perm;
    components[1].checked_permission_known = true;

    AccessPath ap = {.components = components, .count = 2};
    AccessResult result = {
        .allowed = false,
        .reason = reason,
        .blocked_on_traversal = blocked_on_traversal,
        .blocked_path = components[1].path,
        .access_path = &ap,
    };
    return format_remediation(&result, op, "elena", out, out_size);
}

static void check(AccessReason reason, AccessOperation op, PermissionResult perm,
                  mode_t target_mode, bool traversal, const char *expected)
{
    char out[256];
    bool ok = remediation_for(reason, op, perm, target_mode, traversal,
                              out, sizeof(out));
    CHECK(ok);
    CHECK(strcmp(out, expected) == 0);
}

int main(void)
{
    /* Owner lacks the bit on a regular file. */
    check(REASON_OWNER_DENIED, ACCESS_READ, (PermissionResult){0},
          S_IFREG | 0200, false,
          "add the missing permission: chmod u+r /target");

    /* Owner on a directory, write -> the operation bit, not traversal. */
    check(REASON_OWNER_DENIED, ACCESS_WRITE, (PermissionResult){0},
          S_IFDIR | 0500, false,
          "add the missing permission: chmod u+w /target");

    /* In the group but the group bits deny. */
    check(REASON_GROUP_DENIED, ACCESS_READ, (PermissionResult){0},
          S_IFREG | 0600, false,
          "add the permission for the file's group: sudo chmod g+r /target");

    /* Not in the group that would grant it; the group name is resolved. */
    check(REASON_GROUP_MISSING, ACCESS_READ,
          (PermissionResult){.missing_group_gid = 10, .missing_group_known = true},
          S_IFREG | 0640, false,
          "add elena to a group that grants it: sudo usermod -aG wheel elena, "
          "then log in again");

    /* Fallback: no explicit missing group -> the component's own group gid. */
    check(REASON_GROUP_MISSING, ACCESS_READ, (PermissionResult){0},
          S_IFREG | 0640, false,
          "add elena to a group that grants it: sudo usermod -aG wheel elena, "
          "then log in again");

    /* Neither owner nor group: least-privilege ACL grant for just this user.
       The user does not own the file, so the setfacl needs sudo. */
    check(REASON_OTHER_DENIED, ACCESS_READ, (PermissionResult){0},
          S_IFREG | 0640, false,
          "grant only this user via ACL: sudo setfacl -m u:elena:r /target");
    check(REASON_OTHER_DENIED, ACCESS_WRITE, (PermissionResult){0},
          S_IFREG | 0604, false,
          "grant only this user via ACL: sudo setfacl -m u:elena:w /target");
    check(REASON_OTHER_DENIED, ACCESS_EXECUTE, (PermissionResult){0},
          S_IFREG | 0644, false,
          "grant only this user via ACL: sudo setfacl -m u:elena:x /target");

    /* ACL entry exists but does not grant; preserve the bits it already had. */
    check(REASON_ACL_DENIED, ACCESS_READ,
          (PermissionResult){.entry_permissions = 2, .effective_permissions = 2},
          S_IFREG | 0600, false,
          "extend this user's ACL entry: sudo setfacl -m u:elena:rw /target");

    /* The mask, not the entry, is the blocker: widen the mask, keeping its bits. */
    check(REASON_ACL_DENIED, ACCESS_READ,
          (PermissionResult){
              .entry_permissions = 5, .effective_permissions = 1,
              .mask_permissions = 1, .mask_applied = true},
          S_IFREG | 0600, false,
          "widen the ACL mask: sudo setfacl -m m::rx /target");

    /* Mount restrictions are reported as mount options, not permissions. */
    check(REASON_MOUNT_READ_ONLY, ACCESS_WRITE, (PermissionResult){0},
          S_IFREG | 0644, false,
          "this is a read-only mount, not a permission; "
          "remount read-write to allow writes");
    check(REASON_MOUNT_NOEXEC, ACCESS_EXECUTE, (PermissionResult){0},
          S_IFREG | 0755, false,
          "this is a noexec mount, not a permission; "
          "remount without noexec to allow execution");

    /* Blocked on traversal of a parent directory: the needed bit is search. */
    {
        PathComponent components[3] = {0};
        components[0].path = "/";
        components[0].st.st_mode = S_IFDIR | 0755;
        components[1].path = "/private";
        components[1].st.st_mode = S_IFDIR | 0700;
        components[1].checked_permission = (PermissionResult){0};
        components[1].checked_permission_known = true;
        components[2].path = "/private/target";
        AccessPath ap = {.components = components, .count = 3};
        AccessResult result = {
            .allowed = false, .reason = REASON_OWNER_DENIED,
            .blocked_path = components[1].path, .access_path = &ap,
        };
        char out[256];
        CHECK(format_remediation(&result, ACCESS_READ, "elena", out, sizeof(out)));
        CHECK(strcmp(out,
                     "add the missing permission: chmod u+x /private") == 0);
    }

    /* Robustness: no resolved path metadata (blocked component is NULL). The
       formatter must still produce safe advice, defaulting the object to a
       file and resolving a numeric group when none is known. */
    {
        char out[256];
        AccessResult owner = {.allowed = false, .reason = REASON_OWNER_DENIED,
                             .blocked_path = "/x"};
        CHECK(format_remediation(&owner, ACCESS_READ, "elena", out, sizeof(out)));
        CHECK(strcmp(out, "add the missing permission: chmod u+r /x") == 0);

        AccessResult grp = {.allowed = false, .reason = REASON_GROUP_MISSING,
                           .blocked_path = "/x"};
        CHECK(format_remediation(&grp, ACCESS_READ, "elena", out, sizeof(out)));
        CHECK(strcmp(out, "add elena to a group that grants it: "
                          "sudo usermod -aG 0 elena, then log in again") == 0);

        AccessResult acl = {.allowed = false, .reason = REASON_ACL_DENIED,
                           .blocked_path = "/x"};
        CHECK(format_remediation(&acl, ACCESS_READ, "elena", out, sizeof(out)));
        CHECK(strcmp(out,
                     "extend this user's ACL entry: sudo setfacl -m u:elena:r /x") == 0);
    }

    /* No permission-level fix: not-found, loops, broken links, allowed, and a
       path y-not could not inspect (EACCES while resolving it). */
    {
        char out[64];
        AccessResult nf = {.allowed = false, .reason = REASON_NOT_FOUND};
        CHECK(!format_remediation(&nf, ACCESS_READ, "elena", out, sizeof(out)));
        CHECK(out[0] == '\0');

        AccessResult noinspect = {.allowed = false,
                                  .reason = REASON_NOT_TRAVERSABLE,
                                  .blocked_path = "/private/target"};
        CHECK(!format_remediation(&noinspect, ACCESS_READ, "elena", out,
                                  sizeof(out)));
        CHECK(out[0] == '\0');

        AccessResult loop = {.allowed = false, .reason = REASON_SYMLINK_LOOP};
        CHECK(!format_remediation(&loop, ACCESS_READ, "elena", out, sizeof(out)));

        AccessResult broken = {.allowed = false, .reason = REASON_BROKEN_SYMLINK};
        CHECK(!format_remediation(&broken, ACCESS_READ, "elena", out, sizeof(out)));

        AccessResult ok = {.allowed = true, .reason = REASON_NONE};
        CHECK(!format_remediation(&ok, ACCESS_READ, "elena", out, sizeof(out)));
    }

    /* Defensive: a NULL/zero buffer is tolerated, and a NULL user is labeled. */
    {
        char out[256];
        AccessResult r = {.allowed = false, .reason = REASON_OTHER_DENIED,
                          .blocked_path = "/x"};
        CHECK(!format_remediation(&r, ACCESS_READ, "elena", NULL, sizeof(out)));
        CHECK(!format_remediation(&r, ACCESS_READ, "elena", out, 0));
        CHECK(format_remediation(&r, ACCESS_READ, NULL, out, sizeof(out)));
        CHECK(strcmp(out,
                     "grant only this user via ACL: sudo setfacl -m u:USER:r /x") == 0);
    }

    return TEST_SUMMARY();
}
