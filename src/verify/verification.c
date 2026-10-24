#include "verify/verification.h"

/* When a denial does not come from something access(2) can see, probing would
   be misleading rather than confirming. Returns the honest reason to skip, or
   NULL when the decision is safe to verify against the kernel.

   - Inode attributes (immutable, append-only) and the sticky rule are invisible
     to access(2): the model is the more complete answer, so a probe that
     "allowed" the write would wrongly look like a divergence.
   - An unresolved or untraversable path is one y-not could not inspect; a probe
     run with privilege could see past that and contradict the "could not look"
     verdict, inventing a divergence that says nothing real.
   - delete has no access(2) equivalent at all. */
static const char *skip_detail(AccessReason reason)
{
    switch (reason)
    {
    case REASON_IMMUTABLE:
    case REASON_APPEND_ONLY:
    case REASON_STICKY_BIT:
        return "this denial rests on an inode attribute or the sticky rule, "
               "which access(2) cannot check";
    case REASON_NOT_FOUND:
        return "the path could not be resolved to verify";
    case REASON_NOT_TRAVERSABLE:
    case REASON_BROKEN_SYMLINK:
    case REASON_SYMLINK_LOOP:
        return "y-not could not traverse the path to verify";
    case REASON_DELETE_ROOT:
    case REASON_DELETE_SPECIAL:
        return "delete has no kernel access(2) equivalent";
    default:
        return NULL;
    }
}

Verification verification_classify(bool model_allowed, KernelProbe probe)
{
    Verification v = {VERIFICATION_NOT_PROBED, false, NULL};

    if (probe.verdict == KERNEL_PROBE_UNAVAILABLE)
    {
        v.detail = probe.reason;
        return v;
    }

    v.kernel_allowed = (probe.verdict == KERNEL_PROBE_ALLOWED);
    if (v.kernel_allowed == model_allowed)
    {
        v.status = VERIFICATION_CONFIRMED;
        return v;
    }

    v.status = VERIFICATION_DIVERGENT;
    if (model_allowed)
        v.detail =
            "the kernel denies access that owner, group, or ACL permissions "
            "would grant; a security module such as SELinux or AppArmor, or "
            "another policy, is likely enforcing";
    else
        v.detail =
            "the kernel grants access the owner, group, and ACL model expected "
            "to be denied; please report this as a y-not modeling gap";
    return v;
}

Verification verification_evaluate(const AccessResult *result, const User *user,
                                   const char *path, AccessOperation operation)
{
    const char *skip = skip_detail(result->reason);
    if (skip)
    {
        Verification v = {VERIFICATION_NOT_PROBED, false, skip};
        return v;
    }

    /* access(2) resolves the whole path itself; probing the resolved target
       keeps the check faithful to what y-not actually inspected. */
    const char *probe_path = path;
    if (result->access_path && result->access_path->count > 0)
        probe_path =
            result->access_path->components[result->access_path->count - 1].path;

    KernelProbe probe = kernel_probe_access(user, probe_path, operation);
    return verification_classify(result->allowed, probe);
}
