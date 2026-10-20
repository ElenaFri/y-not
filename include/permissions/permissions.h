#pragma once

#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdbool.h>
#include "resolve/user.h"

typedef enum
{
    ACCESS_READ,
    ACCESS_WRITE,
    ACCESS_EXECUTE,
} AccessOperation;

/* Upper bound on the number of candidate groups reported for a missing-group
   denial. POSIX ACLs rarely carry this many granting group entries, and a
   fixed array keeps PermissionResult a plain, copyable value type. */
#define Y_NOT_MAX_CANDIDATE_GROUPS 16

typedef enum
{
    REASON_NONE = 0,
    REASON_OWNER_DENIED,
    REASON_GROUP_DENIED,  /* in group, but group bits deny */
    REASON_GROUP_MISSING, /* not in group; group bits would allow */
    REASON_OTHER_DENIED,
    REASON_ACL_DENIED, /* ACL entry exists but denies this operation */
    REASON_NOT_TRAVERSABLE,
    REASON_NOT_FOUND,
    REASON_BROKEN_SYMLINK, /* symlink whose target does not exist */
    REASON_SYMLINK_LOOP,   /* too many levels of symbolic links */
    REASON_MOUNT_READ_ONLY,
    REASON_MOUNT_NOEXEC,
} AccessReason;

typedef enum
{
    PERMISSION_SOURCE_NONE,
    PERMISSION_SOURCE_UNIX_OWNER,
    PERMISSION_SOURCE_UNIX_GROUP,
    PERMISSION_SOURCE_UNIX_OTHER,
    PERMISSION_SOURCE_ACL_OWNER,
    PERMISSION_SOURCE_ACL_USER,
    PERMISSION_SOURCE_ACL_GROUP,
    PERMISSION_SOURCE_ACL_OTHER,
    PERMISSION_SOURCE_DAC_OVERRIDE,
    PERMISSION_SOURCE_CAP_DAC_OVERRIDE,
    PERMISSION_SOURCE_CAP_DAC_READ_SEARCH,
    PERMISSION_SOURCE_MOUNT,
} PermissionSource;

typedef struct
{
    bool allowed;
    AccessReason reason;
    PermissionSource source;
    unsigned entry_permissions;     /* rwx bitset: read=4, write=2, execute=1 */
    unsigned effective_permissions; /* entry after ACL mask, when applicable */
    unsigned mask_permissions;
    bool mask_applied;
    gid_t missing_group_gid; /* first candidate group; kept for compatibility */
    bool missing_group_known;
    /* Every non-member group whose effective permissions (after any ACL mask)
       would grant the operation. candidate_group_gids[0] mirrors
       missing_group_gid when candidate_group_count > 0. */
    gid_t candidate_group_gids[Y_NOT_MAX_CANDIDATE_GROUPS];
    unsigned candidate_group_count;
} PermissionResult;

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op,
                                      acl_t acl);

/* Apply mount-level restrictions after DAC permission checks. */
AccessReason mount_restriction_reason(bool flags_known, bool read_only,
                                      bool noexec, const struct stat *st,
                                      AccessOperation op);
