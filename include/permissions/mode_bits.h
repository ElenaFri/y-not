#pragma once

#include <sys/stat.h>
#include "permissions/permissions.h"
#include "resolve/user.h"

/* Uniform owner/group/other mode-bit check and group membership test.
   Shared by the plain Unix path and the ACL fallback-to-mode-bits cases. */
bool class_allows(mode_t mode, AccessOperation op, int shift);
bool user_in_group(const User *user, gid_t gid);
