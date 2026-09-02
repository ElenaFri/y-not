#include "../include/apparmor_info.h"
#include "testlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void write_file(const char *path, const char *content)
{
    FILE *f = fopen(path, "w");
    CHECK(f != NULL);
    if (f)
    {
        fputs(content, f);
        fclose(f);
    }
}

int main(void)
{
    char dir[200];
    snprintf(dir, sizeof(dir), "%s/y_not_test_aa_XXXXXX", P_tmpdir);
    CHECK(mkdtemp(dir) != NULL);

    char enabled_path[220], profiles_path[220];
    snprintf(enabled_path, sizeof(enabled_path), "%s/enabled", dir);
    snprintf(profiles_path, sizeof(profiles_path), "%s/profiles", dir);

    /* missing enabled file : not available */
    ApparmorStatus s = apparmor_status_from("/y_not_no_such_enabled_xyz", profiles_path);
    CHECK(!s.available);
    CHECK(s.profile_count == -1);

    /* explicitly disabled */
    write_file(enabled_path, "N\n");
    s = apparmor_status_from(enabled_path, profiles_path);
    CHECK(!s.available);

    /* enabled ("Y"), but profiles file unreadable/missing : count unknown */
    write_file(enabled_path, "Y\n");
    s = apparmor_status_from(enabled_path, "/y_not_no_such_profiles_xyz");
    CHECK(s.available);
    CHECK(s.profile_count == -1);

    /* enabled, profiles readable with 3 entries */
    write_file(profiles_path, "docker-default (enforce)\n"
                              "foo (complain)\n"
                              "bar (enforce)\n");
    s = apparmor_status_from(enabled_path, profiles_path);
    CHECK(s.available);
    CHECK(s.profile_count == 3);

    /* lowercase "y" also counts as enabled */
    write_file(enabled_path, "y\n");
    s = apparmor_status_from(enabled_path, profiles_path);
    CHECK(s.available);

    unlink(enabled_path);
    unlink(profiles_path);
    rmdir(dir);

    /* the real wrapper must not crash regardless of system state */
    (void)apparmor_status();
    CHECK(true);

    return TEST_SUMMARY();
}
