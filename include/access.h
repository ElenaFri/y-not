#pragma once

#include <stdbool.h>
#include "resolve/user.h"
#include "resolve/path.h" /* pulls in permissions.h */

typedef struct
{
    bool allowed;
    char *blocked_path; /* owned; freed by access_result_free() */
    AccessReason reason;
    bool blocked_on_traversal; /* target directory lacked x for an entry operation */
    AccessPath *access_path; /* full breakdown for the renderer */
} AccessResult;

AccessResult check_access(const User *user,
                          const char *path,
                          AccessOperation operation);
void access_result_free(AccessResult *result);

/* Optional multi-account comparison for the "--compare" feature: an explicit,
   caller-supplied list of accounts (never a system-wide enumeration, which
   would be unsound - NSS may be incomplete and MAC is process-dependent) whose
   verdict for the same operation and path was computed to be "allowed". The
   renderers print/emit nothing about comparison unless `requested` is true. */
typedef struct
{
    bool requested;             /* was --compare given? */
    const char *const *allowed; /* names that are allowed; not owned */
    size_t allowed_count;       /* may be 0, meaning "none of them" */
} ComparedUsers;
