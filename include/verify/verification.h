#pragma once

#include "access.h"
#include "verify/kernel_probe.h"

/* Decide what the kernel ground-truth probe tells us about the model's verdict.

   y-not's verdict is always the modeled one: owner/group/ACL, mounts, inode
   attributes, capabilities. The probe is a cross-check, never the verdict. This
   module compares the two and reports one of three honest outcomes, so a user
   can trust the answer and still be warned when the kernel disagrees - most
   usefully when a security module (SELinux, AppArmor) silently overrides DAC. */

typedef enum
{
    VERIFICATION_NOT_PROBED = 0, /* the probe could not or should not run */
    VERIFICATION_CONFIRMED,      /* the kernel agrees with the model */
    VERIFICATION_DIVERGENT,      /* the kernel disagrees with the model */
} VerificationStatus;

typedef struct
{
    VerificationStatus status;
    bool kernel_allowed; /* the kernel's answer; meaningful only when probed */
    const char *detail;  /* static human sentence, or NULL when nothing to add */
} Verification;

/* Classify a model verdict against a probe result. Pure: no I/O, no globals, so
   every outcome is directly testable. An unavailable probe yields NOT_PROBED
   (carrying the probe's own reason); agreement yields CONFIRMED; disagreement
   yields DIVERGENT with a sentence whose wording depends on the direction of
   the disagreement. */
Verification verification_classify(bool model_allowed, KernelProbe probe);

/* Evaluate an access decision against the kernel. Skips the probe - returning
   NOT_PROBED with an honest reason - whenever access(2) would be blind to what
   actually drove the decision (inode attributes, the sticky rule) or whenever
   y-not could not resolve or traverse the path, since a privileged probe would
   then succeed where y-not could not look and manufacture a false divergence.
   Otherwise it asks the kernel about the resolved target and classifies the
   result. */
Verification verification_evaluate(const AccessResult *result, const User *user,
                                   const char *path, AccessOperation operation);
