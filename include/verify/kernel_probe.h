#pragma once

#include "permissions/permissions.h"
#include "resolve/user.h"

/* Ground-truth verification: instead of only modeling the decision, ask the
   kernel itself whether a user may perform an operation on a path, by assuming
   that user's identity and calling access(2). This is a cross-check of the
   model, never part of the verdict. */

typedef enum
{
    KERNEL_PROBE_UNAVAILABLE = 0, /* not run; see `reason` for why */
    KERNEL_PROBE_ALLOWED,
    KERNEL_PROBE_DENIED,
} KernelProbeVerdict;

typedef struct
{
    KernelProbeVerdict verdict;
    const char *reason; /* static string explaining UNAVAILABLE; NULL otherwise */
} KernelProbe;

/* Ask the kernel whether `user` may perform `operation` on `path`.

   When the target user is the one already running y-not, the check runs in the
   current process (no credential change). When it is a different user, y-not
   must drop to that identity in a short-lived child, which needs root; without
   it the probe reports KERNEL_PROBE_UNAVAILABLE with a reason rather than a
   misleading verdict. `delete` has no access(2) equivalent (removal is a
   property of the parent directory plus the sticky rule) and is likewise
   reported as unavailable. */
KernelProbe kernel_probe_access(const User *user, const char *path,
                                AccessOperation operation);
