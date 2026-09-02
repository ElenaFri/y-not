#pragma once

#include <sys/acl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include "permissions.h"

typedef struct
{
    char *path;
    struct stat st;
    acl_t acl; /* NULL when no extended ACL entries */
    bool is_symlink;
    char *symlink_target;  /* NULL unless is_symlink; owned */
    char *file_caps;       /* NULL unless the file has security.capability set; owned */
    char *selinux_context; /* NULL unless SELinux is enabled and the file is labeled; owned */
    bool can_read;
    bool can_write;
    bool can_execute;
    AccessReason denial_reason;
} PathComponent;

typedef struct
{
    PathComponent *components;
    size_t count;
} AccessPath;

/* Decomposes path into components and calls stat(2) on each one. */
AccessPath *path_resolve(const char *path);
void path_free(AccessPath *ap);
