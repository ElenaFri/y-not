#pragma once

#include "access.h"

/* Writes a concrete, minimal remediation suggestion for a *denied* access into
   `buffer`: the least-privilege permission change that would make y-not's
   DAC/ACL model return "allowed". Returns true when a suggestion was written,
   false when no permission-level fix applies (an allowed result, a missing
   path, a broken symlink or a symlink loop).

   The suggestion describes the smallest change to the modeled permissions; it
   preserves bits an entry or mask already grants rather than overwriting them.
   It is advisory only - y-not never runs it, and a read-only or noexec mount is
   reported as a mount option to change, not a permission. */
bool format_remediation(const AccessResult *result, AccessOperation op,
                        const char *user_name, char *buffer, size_t buffer_size);
