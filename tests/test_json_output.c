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

static void check_allowed_case(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;

    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    Capture cap;
    CHECK(begin_capture(&cap));
    render_result_json(&result, "alice", ACCESS_READ, "/target");
    char *json = end_capture(&cap);
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

    free(comps[0].path);
    free(comps[1].path);
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
    AccessResult result = {.allowed = false, .reason = REASON_GROUP_MISSING, .blocked_path = comps[1].path, .access_path = &ap};

    Capture cap;
    CHECK(begin_capture(&cap));
    render_result_json(&result, "bob", ACCESS_EXECUTE, "/blocked/after_the_block");
    char *json = end_capture(&cap);
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

    free(comps[0].path);
    free(comps[1].path);
    free(comps[2].path);
}

static void check_null_access_path_fallback(void)
{
    AccessResult result = {.allowed = false, .reason = REASON_NOT_FOUND, .blocked_path = NULL, .access_path = NULL};

    Capture cap;
    CHECK(begin_capture(&cap));
    render_result_json(&result, "carol", ACCESS_READ, "/y_not_no_such_path");
    char *json = end_capture(&cap);
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
    Capture cap;
    CHECK(begin_capture(&cap));
    render_user_not_found_json("nosuchuser", ACCESS_WRITE, "/etc/passwd");
    char *json = end_capture(&cap);
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
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;

    comps[1].path = strdup("/weird\"name\\here");
    comps[1].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};

    Capture cap;
    CHECK(begin_capture(&cap));
    render_result_json(&result, "dave", ACCESS_READ, comps[1].path);
    char *json = end_capture(&cap);
    CHECK(json != NULL);
    if (json)
    {
        CHECK(strstr(json, "\\\"name\\\\here") != NULL);
        free(json);
    }

    free(comps[0].path);
    free(comps[1].path);
}

int main(void)
{
    check_allowed_case();
    check_denied_case_and_truncation();
    check_null_access_path_fallback();
    check_user_not_found();
    check_string_escaping();
    return TEST_SUMMARY();
}
