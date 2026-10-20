#include "../include/resolve/path.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t count, size_t size);
extern void *__real_realloc(void *ptr, size_t size);
extern char *__real_strdup(const char *string);
extern ssize_t __real_readlink(const char *path, char *buffer, size_t size);
extern int __real_statvfs(const char *path, struct statvfs *info);

typedef enum
{
    ALLOCATOR_NONE,
    ALLOCATOR_MALLOC,
    ALLOCATOR_CALLOC,
    ALLOCATOR_REALLOC,
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

void *__wrap_malloc(size_t size)
{
    return should_fail(ALLOCATOR_MALLOC) ? NULL : __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    return should_fail(ALLOCATOR_CALLOC) ? NULL : __real_calloc(count, size);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    return should_fail(ALLOCATOR_REALLOC) ? NULL : __real_realloc(ptr, size);
}

char *__wrap_strdup(const char *string)
{
    return should_fail(ALLOCATOR_STRDUP) ? NULL : __real_strdup(string);
}

static const char *fail_readlink_path;
static const char *fail_statvfs_path;

ssize_t __wrap_readlink(const char *path, char *buffer, size_t size)
{
    if (fail_readlink_path && strcmp(path, fail_readlink_path) == 0)
    {
        errno = EIO;
        return -1;
    }
    return __real_readlink(path, buffer, size);
}

int __wrap_statvfs(const char *path, struct statvfs *info)
{
    if (fail_statvfs_path && strcmp(path, fail_statvfs_path) == 0)
    {
        errno = EIO;
        return -1;
    }
    return __real_statvfs(path, info);
}

static struct passwd test_account = {
    .pw_name = "y_not_alloc_test",
    .pw_uid = 65001,
    .pw_gid = 650,
};

static bool require_group_growth;

struct passwd *getpwnam(const char *name)
{
    return strcmp(name, test_account.pw_name) == 0 ? &test_account : NULL;
}

int getgrouplist(const char *name, gid_t primary, gid_t *groups, int *count)
{
    (void)name;
    if (require_group_growth && *count < 70)
    {
        *count = 70;
        return -1;
    }
    groups[0] = primary;
    *count = 1;
    return 1;
}

static void check_user_allocation_failures(void)
{
    fail_allocator_call(ALLOCATOR_MALLOC, 1); /* User object */
    User *user = user_lookup(test_account.pw_name);
    failure.allocator = ALLOCATOR_NONE;
    CHECK(user == NULL);

    fail_allocator_call(ALLOCATOR_STRDUP, 1); /* owned username */
    user = user_lookup(test_account.pw_name);
    failure.allocator = ALLOCATOR_NONE;
    CHECK(user == NULL);

    fail_allocator_call(ALLOCATOR_MALLOC, 2); /* supplementary group array */
    user = user_lookup(test_account.pw_name);
    failure.allocator = ALLOCATOR_NONE;
    CHECK(user == NULL);

    require_group_growth = true;
    fail_allocator_call(ALLOCATOR_REALLOC, 1); /* getgrouplist requests growth */
    user = user_lookup(test_account.pw_name);
    failure.allocator = ALLOCATOR_NONE;
    require_group_growth = false;
    CHECK(user == NULL);

    user = user_lookup(test_account.pw_name);
    CHECK(user != NULL);
    if (user)
    {
        CHECK(user->uid == test_account.pw_uid);
        CHECK(user->group_count == 1 && user->groups[0] == test_account.pw_gid);
        user_free(user);
    }
}

static void check_path_inspection_failures(void)
{
    /* A failed readlink should not discard otherwise valid symlink metadata. */
    char directory[] = "./y_not_resolve_fail_XXXXXX";
    bool directory_created = mkdtemp(directory) != NULL;
    CHECK(directory_created);
    if (!directory_created)
        return;
    char cwd[PATH_MAX];
    char link_path[PATH_MAX];
    bool path_ready = getcwd(cwd, sizeof(cwd)) != NULL;
    size_t cwd_length = path_ready ? strlen(cwd) : 0;
    const char *relative_directory = directory + 2;
    size_t relative_length = strlen(relative_directory);
    size_t suffix_length = sizeof("/link") - 1;
    path_ready = path_ready && cwd_length + 1 + relative_length +
                 suffix_length < sizeof(link_path);
    CHECK(path_ready);
    if (!path_ready)
    {
        rmdir(directory);
        return;
    }
    memcpy(link_path, cwd, cwd_length);
    link_path[cwd_length] = '/';
    memcpy(link_path + cwd_length + 1, relative_directory, relative_length);
    memcpy(link_path + cwd_length + 1 + relative_length, "/link",
           suffix_length + 1);
    bool link_created = symlink("/etc/passwd", link_path) == 0;
    CHECK(link_created);
    if (!link_created)
    {
        rmdir(directory);
        return;
    }
    fail_readlink_path = link_path;
    AccessPath *path = path_resolve(link_path);
    fail_readlink_path = NULL;
    CHECK(path != NULL);
    if (path)
    {
        const PathComponent *link = &path->components[path->count - 1];
        CHECK(link->is_symlink);
        CHECK(link->symlink_target == NULL);
        CHECK(link->denial_reason == REASON_NONE);
        path_free(path);
    }
    unlink(link_path);
    rmdir(directory);

    /* statvfs is contextual metadata: failure must not turn a resolvable path
       into a denial, but the mount-flags-known marker must stay clear. */
    fail_statvfs_path = "/etc/passwd";
    path = path_resolve("/etc/passwd");
    fail_statvfs_path = NULL;
    CHECK(path != NULL);
    if (path)
    {
        const PathComponent *file = &path->components[path->count - 1];
        CHECK(file->denial_reason == REASON_NONE);
        CHECK(!file->mount_flags_known);
        path_free(path);
    }
}

static void check_path_allocation_failures(void)
{
    fail_allocator_call(ALLOCATOR_MALLOC, 1); /* AccessPath object */
    AccessPath *path = path_resolve("/");
    failure.allocator = ALLOCATOR_NONE;
    CHECK(path == NULL);

    fail_allocator_call(ALLOCATOR_CALLOC, 1); /* component array */
    path = path_resolve("/");
    failure.allocator = ALLOCATOR_NONE;
    CHECK(path == NULL);

    fail_allocator_call(ALLOCATOR_STRDUP, 1); /* root component */
    path = path_resolve("/");
    failure.allocator = ALLOCATOR_NONE;
    CHECK(path == NULL);

    fail_allocator_call(ALLOCATOR_STRDUP, 2); /* first non-root component */
    path = path_resolve("/var");
    failure.allocator = ALLOCATOR_NONE;
    CHECK(path == NULL);

    fail_allocator_call(ALLOCATOR_STRDUP, 3); /* trailing-slash replacement */
    path = path_resolve("/var/");
    failure.allocator = ALLOCATOR_NONE;
    CHECK(path == NULL);

    path = path_resolve("/");
    CHECK(path != NULL);
    path_free(path);
}

int main(void)
{
    check_user_allocation_failures();
    check_path_inspection_failures();
    check_path_allocation_failures();
    return TEST_SUMMARY();
}
