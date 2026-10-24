#pragma once

#include "access.h"
#include "verify/verification.h"

/* `verification` is the optional kernel cross-check line (NULL to omit it). */
void render_result_text(const AccessResult *result, const User *user,
                        AccessOperation op, const ComparedUsers *compared,
                        const Verification *verification);
