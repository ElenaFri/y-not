#pragma once

#include "access.h"

const char *access_operation_name(AccessOperation op);

/* Returns the path component the denial was reported at (matched by
   blocked_path), or NULL when there is no resolved path to point to. */
const PathComponent *access_blocked_component(const AccessResult *result);

void format_access_explanation(const AccessResult *result, AccessOperation op,
                               char *buffer, size_t buffer_size);
