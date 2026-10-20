#include "../include/render/json_output.h"
#include "../include/access.h"
#include "../include/context/apparmor_info.h"
#include "../include/context/selinux_info.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <acl/libacl.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static struct group mock_group = {.gr_name = "y_not_test_group", .gr_gid = 1234};

struct group *getgrgid(gid_t gid)
{
    return gid == mock_group.gr_gid ? &mock_group : NULL;
}

/* json_output.c queries these to emit the "mac" object; mock them so tests are
   deterministic regardless of the host's actual MAC configuration. Default is
   "no MAC active" so the common cases below never emit a warning. */
static SelinuxStatus mock_selinux;
static ApparmorStatus mock_apparmor;

SelinuxStatus selinux_status(void)
{
    return mock_selinux;
}

ApparmorStatus apparmor_status(void)
{
    return mock_apparmor;
}

typedef struct
{
    int saved_fd;
    char dir[200];
    char path[220];
} Capture;

static bool begin_capture(Capture *c)
{
    snprintf(c->dir, sizeof(c->dir), "%s/y_not_test_json_XXXXXX", P_tmpdir);
    if (!mkdtemp(c->dir))
        return false;
    snprintf(c->path, sizeof(c->path), "%s/out", c->dir);

    int fd = open(c->path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd == -1)
    {
        rmdir(c->dir);
        return false;
    }

    fflush(stdout); /* flush anything buffered before fd 1 changes meaning */
    c->saved_fd = dup(STDOUT_FILENO);
    dup2(fd, STDOUT_FILENO);
    close(fd);
    return true;
}

static char *end_capture(Capture *c)
{
    fflush(stdout);
    dup2(c->saved_fd, STDOUT_FILENO);
    close(c->saved_fd);

    char *buf = NULL;
    FILE *f = fopen(c->path, "r");
    if (f)
    {
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        rewind(f);
        buf = malloc((size_t)size + 1);
        if (buf)
        {
            size_t n = fread(buf, 1, (size_t)size, f);
            buf[n] = '\0';
        }
        fclose(f);
    }
    unlink(c->path);
    rmdir(c->dir);
    return buf;
}

/* Shared by every test below: redirect stdout, call render_result_json(),
   and hand back the captured text. Collapses the repeated capture
   boilerplate that would otherwise duplicate across every check_*(). */
static char *render_and_capture(const AccessResult *result, const char *user,
                                AccessOperation op, const char *path)
{
    Capture cap;
    if (!begin_capture(&cap))
        return NULL;
    render_result_json(result, user, op, path);
    return end_capture(&cap);
}

static char *user_not_found_and_capture(const char *user, AccessOperation op,
                                        const char *path)
{
    Capture cap;
    if (!begin_capture(&cap))
        return NULL;
    render_user_not_found_json(user, op, path);
    return end_capture(&cap);
}

/* The vast majority of cases only need a trivial root + target tree;
   this builds it once instead of repeating the same four lines everywhere. */
static void make_root_and_target(PathComponent comps[2], const char *target_path,
                                 mode_t target_mode)
{
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup(target_path);
    comps[1].st.st_mode = target_mode;
    comps[1].checked_permission_known = true;
    comps[1].checked_permission = (PermissionResult){
        .allowed = true, .reason = REASON_NONE,
        .source = PERMISSION_SOURCE_ACL_USER,
        .entry_permissions = 6, .effective_permissions = 4,
        .mask_permissions = 4, .mask_applied = true,
    };
}

static void free_components(PathComponent *comps, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(comps[i].path);
}

static void check_allowed_case(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"schema_version\": 1") != NULL);
        CHECK(strstr(json, "\"user\": \"alice\"") != NULL);
        CHECK(strstr(json, "\"operation\": \"read\"") != NULL);
        CHECK(strstr(json, "\"path\": \"/target\"") != NULL);
        CHECK(strstr(json, "\"allowed\": true") != NULL);
        CHECK(strstr(json, "\"reason\": \"none\"") != NULL);
        CHECK(strstr(json, "\"blocked_at\": null") != NULL);
        CHECK(strstr(json, "\"checked\": \"read\"") != NULL);
        CHECK(strstr(json, "\"mount_flags\": {\"known\": false") != NULL);
        CHECK(strstr(json, "\"decision\": {\"source\": \"acl_user\"") != NULL);
        CHECK(strstr(json, "\"entry_permissions\": \"rw-\"") != NULL);
        CHECK(strstr(json, "\"effective_permissions\": \"r--\"") != NULL);
        CHECK(strstr(json, "\"missing_group_gid\": null") != NULL);
        free(json);
    }

    free_components(comps, 2);
}

static void check_all_permission_combinations_and_mount_flags(void)
{
    static const char *const permission_text[] = {
        "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};

    for (unsigned bits = 0; bits < 8; bits++)
    {
        PathComponent comps[2] = {0};
        make_root_and_target(comps, "/target", S_IFREG | 0644);
        bool allowed = bits != 0;
        comps[1].checked_permission.allowed = allowed;
        comps[1].checked_permission.reason = allowed ? REASON_NONE : REASON_ACL_DENIED;
        comps[1].checked_permission.entry_permissions = bits;
        comps[1].checked_permission.effective_permissions = bits;
        comps[1].checked_permission.mask_permissions = bits;
        if (!allowed)
            comps[1].denial_reason = REASON_ACL_DENIED;

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = allowed,
                               .reason = allowed ? REASON_NONE : REASON_ACL_DENIED,
                               .blocked_path = allowed ? NULL : comps[1].path,
                               .access_path = &ap};
        AccessOperation op = !allowed ? ACCESS_READ
                             : (bits & 4u) ? ACCESS_READ
                             : (bits & 2u) ? ACCESS_WRITE
                                           : ACCESS_EXECUTE;
        char *json = render_and_capture(&result, "alice", op, "/target");
        CHECK(json != NULL);
        if (json)
        {
            char expected[192];
            snprintf(expected, sizeof(expected),
                     "\"entry_permissions\": \"%s\", \"effective_permissions\": \"%s\", \"mask_applied\": true, \"mask_permissions\": \"%s\"",
                     permission_text[bits], permission_text[bits],
                     permission_text[bits]);
            CHECK(strstr(json, expected) != NULL);
            free(json);
        }
        free_components(comps, 2);
    }

    for (unsigned bits = 0; bits < 8; bits++)
    {
        PathComponent comps[2] = {0};
        make_root_and_target(comps, "/target", S_IFREG | 0644);
        comps[1].mount_flags_known = true;
        comps[1].mount_read_only = (bits & 1u) != 0;
        comps[1].mount_noexec = (bits & 2u) != 0;
        comps[1].mount_nosuid = (bits & 4u) != 0;

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = true, .reason = REASON_NONE,
                               .access_path = &ap};
        char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
        CHECK(json != NULL);
        if (json)
        {
            char expected[192];
            snprintf(expected, sizeof(expected),
                     "\"mount_flags\": {\"known\": true, \"read_only\": %s, \"noexec\": %s, \"nosuid\": %s}",
                     (bits & 1u) ? "true" : "false",
                     (bits & 2u) ? "true" : "false",
                     (bits & 4u) ? "true" : "false");
            CHECK(strstr(json, expected) != NULL);
            free(json);
        }
        free_components(comps, 2);
    }
}

static void check_file_type_and_acl_metadata(void)
{
    static const struct
    {
        mode_t type;
        const char *name;
    } types[] = {
        {S_IFDIR, "directory"},
        {S_IFLNK, "symlink"},
        {S_IFCHR, "character_device"},
        {S_IFBLK, "block_device"},
        {S_IFIFO, "fifo"},
        {S_IFSOCK, "socket"},
        {S_IFREG, "file"},
    };

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    {
        PathComponent comps[2] = {0};
        make_root_and_target(comps, "/target", types[i].type | 0644);
        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = true, .reason = REASON_NONE,
                               .access_path = &ap};
        char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
        CHECK(json != NULL);
        if (json)
        {
            char expected[64];
            snprintf(expected, sizeof(expected), "\"type\": \"%s\"", types[i].name);
            CHECK(strstr(json, expected) != NULL);
            free(json);
        }
        free_components(comps, 2);
    }

    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    acl_t acl = acl_from_text("user::r--,group::r--,other::r--");
    CHECK(acl != NULL);
    if (acl)
    {
        comps[1].acl = acl;
        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = true, .reason = REASON_NONE,
                               .access_path = &ap};
        char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
        CHECK(json != NULL);
        if (json)
        {
            CHECK(strstr(json, "\"has_acl\": true") != NULL);
            free(json);
        }
        acl_free(acl);
    }
    free_components(comps, 2);
}

static void check_missing_group_gid_in_json(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0640);
    comps[1].st.st_gid = 5678;
    comps[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_GROUP_MISSING,
        .source = PERMISSION_SOURCE_ACL_OTHER,
        .missing_group_gid = mock_group.gr_gid,
        .missing_group_known = true,
        .candidate_group_gids = {mock_group.gr_gid, 9999},
        .candidate_group_count = 2};
    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = REASON_GROUP_MISSING,
                           .blocked_path = comps[1].path, .access_path = &ap};
    char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"reason\": \"group_missing\"") != NULL);
        CHECK(strstr(json, "\"missing_group_gid\": 1234") != NULL);
        CHECK(strstr(json,
                     "\"candidate_groups\": [{\"gid\": 1234, \"name\": "
                     "\"y_not_test_group\"},{\"gid\": 9999, \"name\": "
                     "\"9999\"}]") != NULL);
        free(json);
    }
    free_components(comps, 2);
}

static void check_intermediate_unresolved_component(void)
{
    PathComponent comps[3] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup("/private");
    comps[1].denial_reason = REASON_NOT_TRAVERSABLE;
    comps[2].path = strdup("/private/target");
    comps[2].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 3};
    AccessResult result = {.allowed = false, .reason = REASON_NOT_TRAVERSABLE,
                           .blocked_path = comps[1].path, .access_path = &ap};
    char *json = render_and_capture(&result, "alice", ACCESS_READ,
                                   "/private/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"resolved\": false") != NULL);
        CHECK(strstr(json, "\"checked\": \"enter\",\n      \"allowed\": false") != NULL);
        int trace_entries = 0;
        for (const char *p = json; (p = strstr(p, "\"checked\":")) != NULL; p++)
            trace_entries++;
        CHECK(trace_entries == 2);
        free(json);
    }
    free_components(comps, 3);
}

static void check_denied_case_and_truncation(void)
{
    /* three components; the middle one is blocked, the third must not
       appear in the trace at all (truncated, matching the text renderer's
       "don't reveal what's past the block" behavior). */
    PathComponent comps[3] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;

    comps[1].path = strdup("/blocked");
    comps[1].st.st_mode = S_IFDIR | 0750;
    comps[1].st.st_gid = 1001;
    comps[1].denial_reason = REASON_GROUP_MISSING;

    comps[2].path = strdup("/blocked/after_the_block");
    comps[2].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 3};
    AccessResult result = {.allowed = false, .reason = REASON_GROUP_MISSING,
                           .blocked_path = comps[1].path, .access_path = &ap};

    char *json = render_and_capture(&result, "bob", ACCESS_EXECUTE, "/blocked/after_the_block");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"allowed\": false") != NULL);
        CHECK(strstr(json, "\"reason\": \"group_missing\"") != NULL);
        CHECK(strstr(json, "\"blocked_at\": \"/blocked\"") != NULL);
        CHECK(strstr(json, "not in group") != NULL);
        /* the block is on an intermediate directory, so the explanation must
           describe a traversal denial, not the requested execute op */
        CHECK(strstr(json, "which would allow traverse") != NULL);
        /* the trace array itself must stop at the blocked component: count
           per-object markers rather than searching for the string, since
           the top-level "path" field legitimately names the full original
           target regardless of where the trace was truncated. */
        int trace_entries = 0;
        for (const char *p = json; (p = strstr(p, "\"checked\":")) != NULL; p++)
            trace_entries++;
        CHECK(trace_entries == 2);
        free(json);
    }

    free_components(comps, 3);
}

static void check_defensive_unknown_values(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", 0);
    comps[1].checked_permission.source = (PermissionSource)999;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = (AccessReason)999,
                           .blocked_path = "/not-in-trace", .access_path = &ap};
    char *json = render_and_capture(&result, "alice", (AccessOperation)999, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"operation\": \"access\"") != NULL);
        CHECK(strstr(json, "\"reason\": \"unknown\"") != NULL);
        CHECK(strstr(json, "\"explanation\": \"unknown\"") != NULL);
        CHECK(strstr(json, "\"type\": \"unknown\"") != NULL);
        CHECK(strstr(json, "\"source\": \"unknown\"") != NULL);
        free(json);
    }
    free_components(comps, 2);
}

static void check_directory_write_traversal_failure(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup("/target-dir");
    comps[1].st.st_mode = S_IFDIR | 0666;
    comps[1].denial_reason = REASON_OTHER_DENIED;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = REASON_OTHER_DENIED,
                           .blocked_on_traversal = true,
                           .blocked_path = comps[1].path, .access_path = &ap};

    char *json = render_and_capture(&result, "alice", ACCESS_WRITE, "/target-dir");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "no traverse permission") != NULL);
        CHECK(strstr(json, "not in the directory's group") != NULL);
        CHECK(strstr(json, "\"checked\": \"enter\",\n      \"allowed\": false") != NULL);
        free(json);
    }

    free_components(comps, 2);
}

static void check_null_access_path_fallback(void)
{
    AccessResult result = {.allowed = false, .reason = REASON_NOT_FOUND,
                           .blocked_path = NULL, .access_path = NULL};

    char *json = render_and_capture(&result, "carol", ACCESS_READ, "/y_not_no_such_path");
    CHECK(json != NULL);
    if (json)
    {
        /* falls back to the requested path since there is no resolved tree */
        CHECK(strstr(json, "\"path\": \"/y_not_no_such_path\"") != NULL);
        CHECK(strstr(json, "\"reason\": \"not_found\"") != NULL);
        CHECK(strstr(json, "\"trace\": [") != NULL);
        free(json);
    }
}

static void check_user_not_found(void)
{
    char *json = user_not_found_and_capture("nosuchuser", ACCESS_WRITE, "/etc/passwd");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"reason\": \"user_not_found\"") != NULL);
        CHECK(strstr(json, "no such user: nosuchuser") != NULL);
        CHECK(strstr(json, "\"trace\": []") != NULL);
        free(json);
    }
}

static void check_string_escaping(void)
{
    /* a path with an embedded quote and backslash must not break the
       JSON output; the escaped sequences must appear in the raw bytes. */
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/weird\"name\\here", S_IFREG | 0644);

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    char *json = render_and_capture(&result, "dave", ACCESS_READ, comps[1].path);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\\\"name\\\\here") != NULL);
        free(json);
    }

    free_components(comps, 2);
}

/* Every AccessReason must produce a distinct reason_code and explanation;
   the four stat-failure reasons must also mark their trace entry
   "resolved": false instead of printing mode/owner/group fields. */
static const struct
{
    AccessReason reason;
    const char *code;
    bool stat_failed;
} g_reasons[] = {
    {REASON_OWNER_DENIED, "owner_denied", false},
    {REASON_GROUP_DENIED, "group_denied", false},
    {REASON_GROUP_MISSING, "group_missing", false},
    {REASON_OTHER_DENIED, "other_denied", false},
    {REASON_ACL_DENIED, "acl_denied", false},
    {REASON_NOT_TRAVERSABLE, "not_traversable", true},
    {REASON_NOT_FOUND, "not_found", true},
    {REASON_BROKEN_SYMLINK, "broken_symlink", true},
    {REASON_SYMLINK_LOOP, "symlink_loop", true},
    {REASON_MOUNT_READ_ONLY, "mount_read_only", false},
    {REASON_MOUNT_NOEXEC, "mount_noexec", false},
};

static void check_every_reason_message(void)
{
    for (size_t i = 0; i < sizeof(g_reasons) / sizeof(g_reasons[0]); i++)
    {
        PathComponent comps[2] = {0};
        make_root_and_target(comps, "/target", S_IFREG | 0644);
        comps[1].st.st_gid = 1000;
        comps[1].denial_reason = g_reasons[i].reason;

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = false, .reason = g_reasons[i].reason,
                               .blocked_path = comps[1].path, .access_path = &ap};

        AccessOperation operation = g_reasons[i].reason == REASON_OTHER_DENIED
                                        ? ACCESS_EXECUTE
                                        : ACCESS_READ;
        char *json = render_and_capture(&result, "alice", operation, "/target");
        CHECK(json != NULL);
        if (json)
        {
            char expected[64];
            snprintf(expected, sizeof(expected), "\"reason\": \"%s\"", g_reasons[i].code);
            CHECK(strstr(json, expected) != NULL);
            CHECK(strstr(json, g_reasons[i].stat_failed
                             ? "\"resolved\": false"
                             : "\"resolved\": true") != NULL);
            if (g_reasons[i].reason == REASON_OTHER_DENIED)
                CHECK(strstr(json, "file is not marked executable for this user") != NULL);
            free(json);
        }

        free_components(comps, 2);
    }
}

/* Every control character JSON requires escaping, not just " and \. */
static void check_control_character_escaping(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/weird\tname\n\r\x01here", S_IFREG | 0644);

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    char *json = render_and_capture(&result, "erin", ACCESS_READ, comps[1].path);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\\tname\\n\\r\\u0001here") != NULL);
        free(json);
    }

    free_components(comps, 2);
}

/* An unresolvable uid/gid must fall back to the numeric form, not crash. */
static void check_unresolvable_uid_gid(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    comps[1].st.st_uid = 999999;
    comps[1].st.st_gid = 999999;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    char *json = render_and_capture(&result, "frank", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"owner\": \"999999\"") != NULL);
        CHECK(strstr(json, "\"group\": \"999999\"") != NULL);
        free(json);
    }

    free_components(comps, 2);
}

/* The "mac" object is always present and documents MAC honestly: "evaluated"
   is always false, and only an allowed verdict under an active module sets
   "may_override_verdict" true with a non-null warning. */
static void check_mac_block_in_json(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    AccessPath ap = {.components = comps, .count = 2};
    AccessResult allowed = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    /* No MAC active: the block is present, evaluated false, warning null. */
    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};
    char *json = render_and_capture(&allowed, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"mac\": {") != NULL);
        CHECK(strstr(json, "\"selinux\": {\"available\": false, \"enforcing\": null}") != NULL);
        CHECK(strstr(json, "\"apparmor\": {\"available\": false, \"profiles_loaded\": null}") != NULL);
        CHECK(strstr(json, "\"evaluated\": false") != NULL);
        CHECK(strstr(json, "\"may_override_verdict\": false") != NULL);
        CHECK(strstr(json, "\"warning\": null") != NULL);
        free(json);
    }

    /* SELinux enforcing + AppArmor profiles, allowed: warning is populated. */
    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 1};
    mock_apparmor = (ApparmorStatus){.available = true, .profile_count = 4};
    json = render_and_capture(&allowed, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"selinux\": {\"available\": true, \"enforcing\": true}") != NULL);
        CHECK(strstr(json, "\"apparmor\": {\"available\": true, \"profiles_loaded\": 4}") != NULL);
        CHECK(strstr(json, "\"may_override_verdict\": true") != NULL);
        CHECK(strstr(json, "\"warning\": \"this verdict covers DAC/ACL only") != NULL);
        CHECK(strstr(json, "SELinux is enforcing and AppArmor is active") != NULL);
        free(json);
    }

    /* A denial under active MAC: present but not flagged (DAC before MAC). */
    AccessResult denied = {.allowed = false, .reason = REASON_OWNER_DENIED,
                           .blocked_path = comps[1].path, .access_path = &ap};
    comps[1].denial_reason = REASON_OWNER_DENIED;
    json = render_and_capture(&denied, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"may_override_verdict\": false") != NULL);
        CHECK(strstr(json, "\"warning\": null") != NULL);
        free(json);
    }

    /* user-not-found envelope also carries the mac block for schema uniformity. */
    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 0};
    json = user_not_found_and_capture("nosuchuser", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"mac\": {") != NULL);
        CHECK(strstr(json, "\"selinux\": {\"available\": true, \"enforcing\": false}") != NULL);
        CHECK(strstr(json, "\"may_override_verdict\": false") != NULL);
        free(json);
    }

    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};
    free_components(comps, 2);
}

int main(void)
{
    check_allowed_case();
    check_all_permission_combinations_and_mount_flags();
    check_file_type_and_acl_metadata();
    check_missing_group_gid_in_json();
    check_intermediate_unresolved_component();
    check_denied_case_and_truncation();
    check_defensive_unknown_values();
    check_directory_write_traversal_failure();
    check_null_access_path_fallback();
    check_user_not_found();
    check_string_escaping();
    check_every_reason_message();
    check_control_character_escaping();
    check_unresolvable_uid_gid();
    check_mac_block_in_json();
    return TEST_SUMMARY();
}
