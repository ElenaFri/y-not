#include "../include/permissions/capabilities.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static User make_user(uid_t uid, gid_t primary, gid_t *groups, size_t n, char *name)
{
    return (User){.uid = uid, .primary_gid = primary, .groups = groups, .group_count = n, .name = name};
}

/* Writes `content` to a fresh temp file inside a private (0700) directory
   and returns its path in `out` (caller-provided buffer). Uses the
   compile-time P_tmpdir constant, not the TMPDIR environment variable,
   which static analyzers flag as attacker-influenceable. */
static void write_conf(char *out, size_t out_size, const char *content)
{
    char dir[200];
    snprintf(dir, sizeof(dir), "%s/y_not_test_cap_XXXXXX", P_tmpdir);
    CHECK(mkdtemp(dir) != NULL);

    snprintf(out, out_size, "%s/capability.conf", dir);
    FILE *f = fopen(out, "w");
    CHECK(f != NULL);
    if (f)
    {
        fputs(content, f);
        fclose(f);
    }
}

int main(void)
{
    char path[256];

    /* missing file : no grant, no crash */
    User alice = make_user(1000, 1000, NULL, 0, "alice");
    CHECK(!capability_conf_grants("/y_not_no_such_config_xyz", &alice, "cap_dac_override"));

    write_conf(path, sizeof(path), "none *\n");
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_override"));

    write_conf(path, sizeof(path),
               "# comment line, and a blank line follow\n"
               "\n"
               "cap_dac_override       alice\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_override"));
    User bob = make_user(1002, 1002, NULL, 0, "bob");
    CHECK(!capability_conf_grants(path, &bob, "cap_dac_override"));

    /* comma-separated capability list */
    write_conf(path, sizeof(path), "cap_dac_override,cap_chown   alice\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_override"));
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_read_search"));

    /* explicit drop with '!' */
    write_conf(path, sizeof(path), "!cap_dac_override   alice\n");
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_override"));

    /* '*' wildcard matches everyone */
    write_conf(path, sizeof(path), "cap_dac_read_search   *\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_read_search"));
    CHECK(capability_conf_grants(path, &bob, "cap_dac_read_search"));

    /* "all" keyword grants whatever capability is asked about */
    write_conf(path, sizeof(path), "all   alice\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_override"));
    CHECK(capability_conf_grants(path, &alice, "cap_dac_read_search"));

    /* multiple space-separated identities on one line */
    write_conf(path, sizeof(path), "cap_dac_override   someone bob else\n");
    CHECK(capability_conf_grants(path, &bob, "cap_dac_override"));

    /* first matching line wins, even if a later line would also match */
    write_conf(path, sizeof(path),
               "none              alice\n"
               "cap_dac_override  *\n");
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_override"));

    /* @group matches group membership, not just the primary group.
       gid 0 ("root") is guaranteed to exist on any Linux system. */
    User alice_in_root_grp = make_user(1000, 0, NULL, 0, "alice");
    write_conf(path, sizeof(path), "cap_dac_override   @root\n");
    CHECK(capability_conf_grants(path, &alice_in_root_grp, "cap_dac_override"));
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_override")); /* not in that group */

    /* a nonexistent group in "@group" must not match anyone */
    write_conf(path, sizeof(path), "cap_dac_override   @y_not_no_such_group_xyz\n");
    CHECK(!capability_conf_grants(path, &alice, "cap_dac_override"));

    /* '^' (ambient) prefix still counts as granted */
    write_conf(path, sizeof(path), "^cap_dac_override   alice\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_override"));

    /* leading whitespace before the capability spec is tolerated */
    write_conf(path, sizeof(path), "   cap_dac_override   alice\n");
    CHECK(capability_conf_grants(path, &alice, "cap_dac_override"));

    /* the real wrappers must not crash regardless of system config */
    (void)user_has_dac_override(&alice);
    (void)user_has_dac_read_search(&alice);
    CHECK(true);

    return TEST_SUMMARY();
}
