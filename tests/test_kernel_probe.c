#include "../include/verify/kernel_probe.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* A User standing in for the account running the tests, resolved so its
   supplementary groups match the real process. Returns NULL only if the current
   user cannot be looked up, in which case the caller skips. */
static User *current_user(void)
{
    const struct passwd *pw = getpwuid(getuid());
    return pw ? user_lookup(pw->pw_name) : NULL;
}

/* Build a fresh temp directory and a regular file inside it with `file_mode`,
   with the directory traversable (0755). Returns false on setup failure. */
static bool make_file(char *dir, size_t dir_size, char *file, size_t file_size,
                      mode_t file_mode)
{
    snprintf(dir, dir_size, "%s/y_not_probe_test_XXXXXX", P_tmpdir);
    if (!mkdtemp(dir))
        return false;
    snprintf(file, file_size, "%s/target", dir);
    FILE *f = fopen(file, "w");
    if (!f)
        return false;
    fclose(f);
    return chmod(file, file_mode) == 0 && chmod(dir, 0755) == 0;
}

static void cleanup_file(const char *dir, const char *file)
{
    unlink(file);
    rmdir(dir);
}

/* delete is not expressible via access(2); it must always be reported as
   unavailable, with a reason, regardless of the path. */
static void check_delete_is_unavailable(void)
{
    User *me = current_user();
    if (!me)
        return;
    KernelProbe probe = kernel_probe_access(me, "/usr/bin/ls", ACCESS_DELETE);
    CHECK(probe.verdict == KERNEL_PROBE_UNAVAILABLE);
    CHECK(probe.reason != NULL);
    user_free(me);
}

/* Probing the account that runs y-not needs no privilege and no fork: a file we
   own and can read is allowed; execute on a file with no x bits is denied even
   for root (X_OK needs at least one execute bit). */
static void check_current_user_in_process(void)
{
    User *me = current_user();
    if (!me)
        return;

    char dir[256], file[sizeof(dir) + 16];
    if (!make_file(dir, sizeof(dir), file, sizeof(file), 0644))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    KernelProbe readable = kernel_probe_access(me, file, ACCESS_READ);
    CHECK(readable.verdict == KERNEL_PROBE_ALLOWED);
    CHECK(readable.reason == NULL);

    KernelProbe writable = kernel_probe_access(me, file, ACCESS_WRITE);
    CHECK(writable.verdict == KERNEL_PROBE_ALLOWED);

    KernelProbe executable = kernel_probe_access(me, file, ACCESS_EXECUTE);
    CHECK(executable.verdict == KERNEL_PROBE_DENIED);

    cleanup_file(dir, file);
    user_free(me);
}

/* A directory write is probed as write AND search: a directory with write but
   no execute bit (0600) cannot receive new entries, so the probe denies it -
   but only for an unprivileged user. Root's DAC_OVERRIDE grants search on any
   directory regardless of its mode bits (the "needs at least one execute bit"
   rule applies to regular files, not directories), so the denial can only be
   demonstrated when not running as root. */
static void check_directory_write_needs_search(void)
{
    User *me = current_user();
    if (!me)
        return;

    char dir[256];
    snprintf(dir, sizeof(dir), "%s/y_not_probe_dir_XXXXXX", P_tmpdir);
    if (!mkdtemp(dir))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    CHECK(chmod(dir, 0755) == 0);
    KernelProbe open_dir = kernel_probe_access(me, dir, ACCESS_WRITE);
    CHECK(open_dir.verdict == KERNEL_PROBE_ALLOWED);

    if (geteuid() != 0)
    {
        CHECK(chmod(dir, 0600) == 0);
        KernelProbe no_search = kernel_probe_access(me, dir, ACCESS_WRITE);
        CHECK(no_search.verdict == KERNEL_PROBE_DENIED);
    }

    chmod(dir, 0700); /* restore so cleanup can remove it */
    rmdir(dir);
    user_free(me);
}

/* A write probe stats the path first; a path that does not exist is denied
   rather than crashing. */
static void check_missing_path_write_is_denied(void)
{
    User *me = current_user();
    if (!me)
        return;
    KernelProbe probe =
        kernel_probe_access(me, "/y_not_no_such_path_for_probe", ACCESS_WRITE);
    CHECK(probe.verdict == KERNEL_PROBE_DENIED);
    user_free(me);
}

/* Probing a *different* user is only sound when we can become them. As an
   ordinary user we cannot, so the probe is unavailable with a reason; as root
   we fork, drop to the user, and get a real verdict. */
static void check_other_user(void)
{
    if (geteuid() != 0)
    {
        uid_t other = getuid() == 0 ? 1 : 0;
        User synthetic = {.uid = other, .primary_gid = 0, .groups = NULL,
                          .group_count = 0, .name = "y_not_other"};
        KernelProbe probe =
            kernel_probe_access(&synthetic, "/usr/bin/ls", ACCESS_READ);
        CHECK(probe.verdict == KERNEL_PROBE_UNAVAILABLE);
        CHECK(probe.reason != NULL);
        return;
    }

    const struct passwd *nobody = getpwnam("nobody");
    if (!nobody)
        return;
    User target = {.uid = nobody->pw_uid, .primary_gid = nobody->pw_gid,
                   .groups = NULL, .group_count = 0, .name = "nobody"};

    /* nobody can read a world-readable system binary. */
    KernelProbe allowed = kernel_probe_access(&target, "/usr/bin/ls", ACCESS_READ);
    CHECK(allowed.verdict == KERNEL_PROBE_ALLOWED);

    /* nobody cannot reach a file inside a 0700 directory owned by root. */
    char dir[256], file[sizeof(dir) + 16];
    if (make_file(dir, sizeof(dir), file, sizeof(file), 0644) &&
        chmod(dir, 0700) == 0)
    {
        KernelProbe denied = kernel_probe_access(&target, file, ACCESS_READ);
        CHECK(denied.verdict == KERNEL_PROBE_DENIED);
        chmod(dir, 0755);
        cleanup_file(dir, file);
    }
}

int main(void)
{
    check_delete_is_unavailable();
    check_current_user_in_process();
    check_directory_write_needs_search();
    check_missing_path_write_is_denied();
    check_other_user();
    return TEST_SUMMARY();
}
