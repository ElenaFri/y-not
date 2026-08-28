#pragma once

#include <sys/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include "permissions.h"

typedef struct
{
    char *path;
    struct stat st;
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
