#include "../include/context/selinux_info.h"
#include "testlib.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    /* Purely a smoke check on this dev machine's actual state: the
       function must never crash, and its contract must hold either way. */
    SelinuxStatus s = selinux_status();
    if (s.available)
        CHECK(s.enforcing == 0 || s.enforcing == 1);
    else
        CHECK(s.enforcing == -1);

    /* A plain, unlabeled-by-us temp file: NULL unless SELinux is enabled
       AND the filesystem actually carries a label for it (both must hold;
       neither is guaranteed here, so we only check the disabled case). */
    char dir[200];
    snprintf(dir, sizeof(dir), "%s/y_not_test_se_XXXXXX", P_tmpdir);
    CHECK(mkdtemp(dir) != NULL);

    char path[220];
    snprintf(path, sizeof(path), "%s/plain", dir);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0700);
    CHECK(fd != -1);
    if (fd != -1)
    {
        close(fd);
        char *ctx = selinux_file_context(path);
        if (!s.available)
            CHECK(ctx == NULL);
        free(ctx);
        unlink(path);
    }
    rmdir(dir);

    /* A path that cannot possibly exist: never returns a context. */
    CHECK(selinux_file_context("/y_not_no_such_path_xyz") == NULL);

    return TEST_SUMMARY();
}
