#include "verify/kernel_probe.h"

#include <grp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Does the kernel grant `operation` on `path` to whoever this process now is?
   Runs under the caller's current credentials, so it must only be reached after
   the identity has been established (either natively or via the child below).

   Creating an entry in a directory needs both write and search on it, so a
   directory write is probed with W_OK and X_OK together; for a regular file,
   W_OK alone is the write check. access(2) resolves the whole path, so a missing
   traversal permission on any parent already makes it fail. */
static bool kernel_grants(const char *path, AccessOperation operation)
{
    switch (operation)
    {
    case ACCESS_READ:
        return access(path, R_OK) == 0;
    case ACCESS_EXECUTE:
        return access(path, X_OK) == 0;
    case ACCESS_WRITE:
    {
        struct stat st;
        if (stat(path, &st) != 0)
            return false;
        if (S_ISDIR(st.st_mode))
            return access(path, W_OK) == 0 && access(path, X_OK) == 0;
        return access(path, W_OK) == 0;
    }
    default:
        return false;
    }
}

/* Decode a child exit status into a probe verdict: 0 = allowed, 1 = denied,
   anything else (e.g. the identity drop failed) = could not probe. */
static KernelProbe verdict_from_child(int status)
{
    KernelProbe probe = {KERNEL_PROBE_UNAVAILABLE, NULL};
    if (!WIFEXITED(status))
    {
        probe.reason = "the verification probe did not complete";
        return probe;
    }
    switch (WEXITSTATUS(status))
    {
    case 0:
        probe.verdict = KERNEL_PROBE_ALLOWED;
        break;
    case 1:
        probe.verdict = KERNEL_PROBE_DENIED;
        break;
    default:
        probe.reason = "could not assume the user's identity to verify";
        break;
    }
    return probe;
}

/* Fork, drop to the target identity, and probe. Only used when the target
   differs from the running user, which requires privilege to impersonate. */
static KernelProbe probe_as_other_user(const User *user, const char *path,
                                       AccessOperation operation)
{
    KernelProbe probe = {KERNEL_PROBE_UNAVAILABLE, NULL};

    pid_t child = fork();
    if (child == -1)
    {
        probe.reason = "could not fork to assume the user's identity";
        return probe;
    }
    if (child == 0)
    {
        if (setgroups(user->group_count, user->groups) != 0 ||
            setgid(user->primary_gid) != 0 || setuid(user->uid) != 0)
            _exit(2);
        _exit(kernel_grants(path, operation) ? 0 : 1);
    }

    int status;
    if (waitpid(child, &status, 0) != child)
    {
        probe.reason = "the verification probe did not complete";
        return probe;
    }
    return verdict_from_child(status);
}

KernelProbe kernel_probe_access(const User *user, const char *path,
                                AccessOperation operation)
{
    KernelProbe probe = {KERNEL_PROBE_UNAVAILABLE, NULL};

    if (operation == ACCESS_DELETE)
    {
        probe.reason = "delete has no kernel access(2) equivalent";
        return probe;
    }

    /* Same user as the one running y-not: our process already carries this
       identity (real uid and supplementary groups), so probe in place without
       touching credentials. */
    if (user->uid == getuid())
    {
        probe.verdict =
            kernel_grants(path, operation) ? KERNEL_PROBE_ALLOWED : KERNEL_PROBE_DENIED;
        return probe;
    }

    if (geteuid() != 0)
    {
        probe.reason = "requires root to verify as another user";
        return probe;
    }

    return probe_as_other_user(user, path, operation);
}
