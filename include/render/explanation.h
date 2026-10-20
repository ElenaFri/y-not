#pragma once

#include "access.h"

const char *access_operation_name(AccessOperation op);
void format_access_explanation(const AccessResult *result, AccessOperation op,
                               char *buffer, size_t buffer_size);
