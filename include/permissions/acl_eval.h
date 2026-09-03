#pragma once

#include <sys/acl.h>
#include <sys/stat.h>
#include "permissions/mode_bits.h"
#include "permissions/permissions.h"
#include "resolve/user.h"

/* Full POSIX ACL evaluation: owner entry, named user/group entries with
   mask, group-object, other. Called by evaluate_permissions() whenever a
   component carries an extended ACL. */
PermissionResult evaluate_acl_permissions(const User *user,
                                          const struct stat *st,
                                          AccessOperation op,
                                          acl_t acl);
