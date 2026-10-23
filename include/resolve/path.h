#pragma once

#include <sys/acl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include "permissions/permissions.h"

typedef struct
{
    char *path;
    struct stat st;
    struct stat link_st; /* lstat(2) metadata; differs from st for a symlink */
    bool link_st_known;
    acl_t acl; /* NULL when no extended ACL entries */
    bool is_symlink;
    char *symlink_target;  /* NULL unless is_symlink; owned */
    char *file_caps;       /* NULL unless the file has security.capability set; owned */
    char *selinux_context; /* NULL unless SELinux is enabled and the file is labeled; owned */
    bool mount_flags_known;
    bool mount_read_only;
    bool mount_noexec;
    bool mount_nosuid;
    bool can_read;
    bool can_write;
    bool can_execute;
    PermissionResult checked_permission;
    bool checked_permission_known;
    AccessReason denial_reason;
} PathComponent;

typedef struct
{
    PathComponent *components;
    size_t count;
} AccessPath;

/* Builds a trace from lexical path prefixes and inspects each with lstat(2)/stat(2).
   Dot segments are intentionally retained: the kernel must interpret them after
   following any preceding symlink (notably for link/.. paths). */
AccessPath *path_resolve(const char *path);
void path_free(AccessPath *ap);
