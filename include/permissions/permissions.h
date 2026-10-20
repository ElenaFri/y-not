#pragma once

#include <sys/acl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "resolve/user.h"

typedef enum
{
    ACCESS_READ,
    ACCESS_WRITE,
    ACCESS_EXECUTE,
} AccessOperation;

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

typedef struct
{
    bool allowed;
    AccessReason reason;
} PermissionResult;

PermissionResult evaluate_permissions(const User *user,
                                      const struct stat *st,
                                      AccessOperation op,
                                      acl_t acl);

/* Apply mount-level restrictions after DAC permission checks. */
AccessReason mount_restriction_reason(bool flags_known, bool read_only,
                                      bool noexec, const struct stat *st,
                                      AccessOperation op);
