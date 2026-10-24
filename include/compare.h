#pragma once

#include <stddef.h>
#include "access.h"

/* Resolves which accounts from a comma-separated `list` are allowed `operation`
   on `path`, used by the --compare feature. The list is explicit and
   caller-supplied by design: y-not never enumerates the whole system, because
   NSS may be incomplete and MAC confinement is process-dependent, so an
   exhaustive "who can" answer could not be sound.

   Empty tokens, duplicates, and `primary` (the main user being explained) are
   skipped; names that do not resolve to a user are silently dropped. Returns a
   malloc'd array of strdup'd account names - each entry and the array itself
   must be freed by the caller - and writes the number of entries to
   *out_count. Returns NULL (with *out_count set to 0) only on allocation
   failure. */
char **compare_allowed_accounts(const char *list, const char *primary,
                                const char *path, AccessOperation operation,
                                size_t *out_count);
