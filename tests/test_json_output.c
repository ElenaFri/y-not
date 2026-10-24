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
    render_result_json(result, user, op, path, NULL, NULL);
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

/* Capture variant that drives the --compare path, so the additive
   "allowed_for" array is emitted. */
static char *compare_and_capture(const AccessResult *result, const char *user,
                                 AccessOperation op, const char *path,
                                 const ComparedUsers *compared)
{
    Capture cap;
    if (!begin_capture(&cap))
        return NULL;
    render_result_json(result, user, op, path, compared, NULL);
    return end_capture(&cap);
}

/* Capture variant that drives the kernel cross-check, so the additive
   "verification" object is emitted. */
static char *verify_and_capture(const AccessResult *result, const char *user,
                                AccessOperation op, const char *path,
                                const Verification *verification)
{
    Capture cap;
    if (!begin_capture(&cap))
        return NULL;
    render_result_json(result, user, op, path, NULL, verification);
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

/* When this combo is denied (bits == 0) y-not reports a read denial; otherwise
   the first rwx bit present names the operation. */
static AccessOperation op_for_bits(bool allowed, unsigned bits)
{
    if (!allowed || (bits & 4u))
        return ACCESS_READ;
    if (bits & 2u)
        return ACCESS_WRITE;
    return ACCESS_EXECUTE;
}

static void check_all_permission_combinations(void)
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
        AccessOperation op = op_for_bits(allowed, bits);
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
}

static void check_mount_flag_combinations(void)
{
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
        const char *p = json;
        while ((p = strstr(p, "\"checked\":")) != NULL)
        {
            trace_entries++;
            p++;
        }
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
        const char *p = json;
        while ((p = strstr(p, "\"checked\":")) != NULL)
        {
            trace_entries++;
            p++;
        }
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
    {REASON_STICKY_BIT, "sticky_bit", false},
    {REASON_DELETE_ROOT, "delete_root", false},
    {REASON_DELETE_SPECIAL, "delete_special", false},
    {REASON_IMMUTABLE, "immutable", false},
    {REASON_APPEND_ONLY, "append_only", false},
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

/* delete denials add an `entry_owner` field on the target component (the owner
   of the entry itself, from lstat) in both the resolved and stat-failed trace
   branches, and the sticky/root/special reasons get their own codes. */
static void check_delete_json(void)
{
    /* Sticky denial: the target resolves, so entry_owner sits beside owner. */
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/uploads/report.csv", S_IFREG | 0644);
    comps[1].checked_permission_known = false;
    comps[1].denial_reason = REASON_STICKY_BIT;
    comps[1].link_st_known = true;
    comps[1].link_st.st_uid = 1234;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = REASON_STICKY_BIT,
                           .blocked_path = comps[1].path, .access_path = &ap};

    char *json = render_and_capture(&result, "bob", ACCESS_DELETE,
                                    "/uploads/report.csv");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"reason\": \"sticky_bit\"") != NULL);
        CHECK(strstr(json, "\"resolved\": true") != NULL);
        CHECK(strstr(json, "\"entry_owner\": \"1234\"") != NULL);
        CHECK(strstr(json, "\"remediation\": \"take ownership") != NULL);
        free(json);
    }
    free_components(comps, 2);

    /* A broken-symlink delete target is unresolved, yet lstat succeeded on the
       link itself, so entry_owner is still reported in the stat-failed branch. */
    PathComponent comps2[2] = {0};
    make_root_and_target(comps2, "/uploads/link", S_IFLNK | 0777);
    comps2[1].checked_permission_known = false;
    comps2[1].denial_reason = REASON_BROKEN_SYMLINK;
    comps2[1].link_st_known = true;
    comps2[1].link_st.st_uid = 1234;

    AccessPath ap2 = {.components = comps2, .count = 2};
    AccessResult result2 = {.allowed = false, .reason = REASON_BROKEN_SYMLINK,
                            .blocked_path = comps2[1].path, .access_path = &ap2};

    char *json2 = render_and_capture(&result2, "bob", ACCESS_DELETE,
                                     "/uploads/link");
    CHECK(json2 != NULL);
    if (json2)
    {
        CHECK(strstr(json2, "\"resolved\": false") != NULL);
        CHECK(strstr(json2, "\"entry_owner\": \"1234\"") != NULL);
        free(json2);
    }
    free_components(comps2, 2);
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
        /* The denied envelope carries a remediation string, not null. */
        CHECK(strstr(json, "\"remediation\": \"add the missing permission: chmod u+r") != NULL);
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
        CHECK(strstr(json, "\"remediation\": null") != NULL);
        free(json);
    }

    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};
    free_components(comps, 2);
}

/* Inode-attribute denials surface the fs_attr source in the decision block and
   a chattr remediation, for both immutable (write) and append-only (delete). */
static void check_attribute_json(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    comps[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_IMMUTABLE,
        .source = PERMISSION_SOURCE_FS_ATTR};
    comps[1].checked_permission_known = true;
    comps[1].denial_reason = REASON_IMMUTABLE;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = REASON_IMMUTABLE,
                           .blocked_path = comps[1].path, .access_path = &ap};
    char *json = render_and_capture(&result, "alice", ACCESS_WRITE, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"reason\": \"immutable\"") != NULL);
        CHECK(strstr(json, "\"source\": \"fs_attr\"") != NULL);
        CHECK(strstr(json, "\"remediation\": \"clear the immutable attribute") != NULL);
        free(json);
    }
    free_components(comps, 2);

    PathComponent comps2[2] = {0};
    make_root_and_target(comps2, "/target", S_IFREG | 0644);
    comps2[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_APPEND_ONLY,
        .source = PERMISSION_SOURCE_FS_ATTR};
    comps2[1].checked_permission_known = true;
    comps2[1].denial_reason = REASON_APPEND_ONLY;
    comps2[1].link_st_known = true;
    comps2[1].link_st.st_uid = 1000;

    AccessPath ap2 = {.components = comps2, .count = 2};
    AccessResult result2 = {.allowed = false, .reason = REASON_APPEND_ONLY,
                            .blocked_path = comps2[1].path, .access_path = &ap2};
    char *json2 = render_and_capture(&result2, "alice", ACCESS_DELETE, "/target");
    CHECK(json2 != NULL);
    if (json2)
    {
        CHECK(strstr(json2, "\"reason\": \"append_only\"") != NULL);
        CHECK(strstr(json2, "\"source\": \"fs_attr\"") != NULL);
        CHECK(strstr(json2, "\"remediation\": \"clear the append-only attribute") != NULL);
        free(json2);
    }
    free_components(comps2, 2);
}

/* --compare adds an "allowed_for" array only when requested: the listed names
   when some accounts are allowed, an empty array when none are, and the key is
   absent entirely otherwise (so the base schema gains nothing it must handle).
   Names are escaped like any other JSON string. */
static void check_allowed_for_array(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    const char *names[] = {"root", "back\"up"};
    ComparedUsers some = {.requested = true, .allowed = names, .allowed_count = 2};
    ComparedUsers none = {.requested = true, .allowed = NULL, .allowed_count = 0};
    ComparedUsers off = {0};

    char *json = compare_and_capture(&result, "alice", ACCESS_READ, "/target", &some);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"allowed_for\": [\"root\",\"back\\\"up\"]") != NULL);
        free(json);
    }

    json = compare_and_capture(&result, "alice", ACCESS_READ, "/target", &none);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"allowed_for\": []") != NULL);
        free(json);
    }

    json = compare_and_capture(&result, "alice", ACCESS_READ, "/target", &off);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "allowed_for") == NULL);
        free(json);
    }

    free_components(comps, 2);
}

/* The additive "verification" object mirrors the Verification struct: the three
   statuses, a "kernel_allowed" that is a boolean when probed and null when not,
   and a "detail" that is a string or null. The key is additive, so it only
   appears when a Verification was handed to the renderer. */
static void check_verification_object(void)
{
    PathComponent comps[2] = {0};
    make_root_and_target(comps, "/target", S_IFREG | 0644);
    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};

    /* CONFIRMED: status string, kernel_allowed true, detail null. */
    Verification confirmed = {.status = VERIFICATION_CONFIRMED, .kernel_allowed = true};
    char *json = verify_and_capture(&result, "alice", ACCESS_READ, "/target", &confirmed);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"verification\": {\"status\": \"confirmed\", "
                            "\"kernel_allowed\": true, \"detail\": null}") != NULL);
        free(json);
    }

    /* DIVERGENT: kernel_allowed false, detail string present. */
    Verification divergent = {.status = VERIFICATION_DIVERGENT, .kernel_allowed = false,
                             .detail = "the kernel denies this although the model allows it"};
    json = verify_and_capture(&result, "alice", ACCESS_READ, "/target", &divergent);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"status\": \"divergent\"") != NULL);
        CHECK(strstr(json, "\"kernel_allowed\": false") != NULL);
        CHECK(strstr(json, "the kernel denies this although the model allows it") != NULL);
        free(json);
    }

    /* NOT_PROBED: kernel_allowed null, detail carries the honest reason. */
    Verification not_probed = {.status = VERIFICATION_NOT_PROBED,
                              .detail = "requires root to verify as another user"};
    json = verify_and_capture(&result, "alice", ACCESS_READ, "/target", &not_probed);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"status\": \"not_probed\"") != NULL);
        CHECK(strstr(json, "\"kernel_allowed\": null") != NULL);
        CHECK(strstr(json, "requires root to verify as another user") != NULL);
        free(json);
    }

    /* NOT_PROBED with no detail: status present, detail null. */
    Verification silent = {.status = VERIFICATION_NOT_PROBED, .detail = NULL};
    json = verify_and_capture(&result, "alice", ACCESS_READ, "/target", &silent);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\"status\": \"not_probed\", \"kernel_allowed\": null, "
                            "\"detail\": null") != NULL);
        free(json);
    }

    /* No Verification handed in: the key is absent entirely. */
    json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "verification") == NULL);
        free(json);
    }

    free_components(comps, 2);
}

int main(void)
{
    check_allowed_case();
    check_all_permission_combinations();
    check_mount_flag_combinations();
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
    check_delete_json();
    check_attribute_json();
    check_allowed_for_array();
    check_verification_object();
    return TEST_SUMMARY();
}
