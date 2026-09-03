#include "../include/render/json_output.h"
#include "../include/access.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

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
        free(json);
    }

    free_components(comps, 2);
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

        char *json = render_and_capture(&result, "alice", ACCESS_READ, "/target");
        CHECK(json != NULL);
        if (json)
        {
            char expected[64];
            snprintf(expected, sizeof(expected), "\"reason\": \"%s\"", g_reasons[i].code);
            CHECK(strstr(json, expected) != NULL);
            CHECK(strstr(json, g_reasons[i].stat_failed
                             ? "\"resolved\": false"
                             : "\"resolved\": true") != NULL);
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

int main(void)
{
    check_allowed_case();
    check_denied_case_and_truncation();
    check_null_access_path_fallback();
    check_user_not_found();
    check_string_escaping();
    check_every_reason_message();
    check_control_character_escaping();
    check_unresolvable_uid_gid();
    return TEST_SUMMARY();
}
