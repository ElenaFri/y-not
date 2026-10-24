#include "../include/compare.h"
#include "testlib.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Deterministic allocation-failure injection, mirroring test_resolve_failures:
   compare_allowed_accounts()'s very first allocation is strdup(list), and its
   first two calloc()s (the result and the dedup arrays) run before any
   user_lookup(), so failing call N of a given allocator is reproducible. */
extern void *__real_calloc(size_t count, size_t size);
extern char *__real_strdup(const char *string);

typedef enum
{
    ALLOCATOR_NONE,
    ALLOCATOR_CALLOC,
    ALLOCATOR_STRDUP,
} Allocator;

static struct
{
    Allocator allocator;
    unsigned fail_on_call;
    unsigned calls;
} failure;

static void fail_allocator_call(Allocator allocator, unsigned call)
{
    failure.allocator = allocator;
    failure.fail_on_call = call;
    failure.calls = 0;
}

static bool should_fail(Allocator allocator)
{
    if (failure.allocator != allocator)
        return false;
    failure.calls++;
    if (failure.calls != failure.fail_on_call)
        return false;
    failure.allocator = ALLOCATOR_NONE;
    return true;
}

void *__wrap_calloc(size_t count, size_t size)
{
    return should_fail(ALLOCATOR_CALLOC) ? NULL : __real_calloc(count, size);
}

char *__wrap_strdup(const char *string)
{
    return should_fail(ALLOCATOR_STRDUP) ? NULL : __real_strdup(string);
}

static bool list_contains(char **names, size_t count, const char *needle)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(names[i], needle) == 0)
            return true;
    return false;
}

static void free_list(char **names, size_t count)
{
    for (size_t i = 0; i < count; i++)
        free(names[i]);
    free(names);
}

/* root can read any world-unreadable-irrelevant path via its DAC override, so
   it is a deterministic "allowed" entry regardless of who runs the test. */
static void check_allowed_account_is_listed(void)
{
    size_t count = 0;
    char **names = compare_allowed_accounts("root", "primary_not_used",
                                            "/usr/bin/ls", ACCESS_READ, &count);
    CHECK(names != NULL);
    CHECK(count == 1);
    if (names)
    {
        CHECK(list_contains(names, count, "root"));
        free_list(names, count);
    }
}

/* The primary user is never compared against itself. */
static void check_primary_is_excluded(void)
{
    size_t count = 0;
    char **names = compare_allowed_accounts("root", "root",
                                            "/usr/bin/ls", ACCESS_READ, &count);
    CHECK(names != NULL);
    CHECK(count == 0);
    free_list(names, count);
}

/* A name repeated in the list is evaluated once (covers the dedup branch). */
static void check_duplicates_are_collapsed(void)
{
    size_t count = 0;
    char **names = compare_allowed_accounts("root,root", "primary_not_used",
                                            "/usr/bin/ls", ACCESS_READ, &count);
    CHECK(names != NULL);
    CHECK(count == 1);
    free_list(names, count);
}

/* Unknown names and empty tokens are silently dropped, not errors. */
static void check_unknown_and_empty_tokens_are_dropped(void)
{
    size_t count = 0;
    char **names = compare_allowed_accounts("__y_not_no_such_user__,,root",
                                            "primary_not_used", "/usr/bin/ls",
                                            ACCESS_READ, &count);
    CHECK(names != NULL);
    CHECK(count == 1);
    if (names)
    {
        CHECK(list_contains(names, count, "root"));
        free_list(names, count);
    }
}

/* A compared account that is denied the operation must not appear in the list
   (covers the "allowed?" false branch). "nobody" cannot traverse a 0700
   directory it does not own, so reading a file inside is denied for it. */
static void check_denied_account_is_not_listed(void)
{
    /* Use the compile-time P_tmpdir constant rather than the TMPDIR
       environment variable, which static analyzers flag as attacker-
       influenceable when used to build a filesystem path. */
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/y_not_compare_test_XXXXXX", P_tmpdir);
    if (!mkdtemp(dir))
    {
        CHECK(false);
        return;
    }
    char file[sizeof(dir) + 16];
    snprintf(file, sizeof(file), "%s/inner", dir);
    FILE *f = fopen(file, "w");
    if (f)
        fclose(f);
    CHECK(chmod(dir, 0700) == 0);

    size_t count = 0;
    char **names = compare_allowed_accounts("nobody", "primary_not_used",
                                            file, ACCESS_READ, &count);
    CHECK(names != NULL);
    CHECK(!list_contains(names, count, "nobody"));
    free_list(names, count);

    unlink(file);
    rmdir(dir);
}

/* Allocation-failure paths return NULL cleanly without leaking. */
static void check_allocation_failures(void)
{
    size_t count = 99;

    /* strdup(list) fails first. */
    fail_allocator_call(ALLOCATOR_STRDUP, 1);
    char **names = compare_allowed_accounts("root", "x", "/usr/bin/ls",
                                            ACCESS_READ, &count);
    CHECK(names == NULL);
    CHECK(count == 0);

    /* the result array (first calloc) fails. */
    count = 99;
    fail_allocator_call(ALLOCATOR_CALLOC, 1);
    names = compare_allowed_accounts("root", "x", "/usr/bin/ls",
                                     ACCESS_READ, &count);
    CHECK(names == NULL);
    CHECK(count == 0);

    /* the dedup array (second calloc) fails. */
    count = 99;
    fail_allocator_call(ALLOCATOR_CALLOC, 2);
    names = compare_allowed_accounts("root", "x", "/usr/bin/ls",
                                     ACCESS_READ, &count);
    CHECK(names == NULL);
    CHECK(count == 0);
}

int main(void)
{
    check_allowed_account_is_listed();
    check_primary_is_excluded();
    check_duplicates_are_collapsed();
    check_unknown_and_empty_tokens_are_dropped();
    check_denied_account_is_not_listed();
    check_allocation_failures();
    return TEST_SUMMARY();
}
