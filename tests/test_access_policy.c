#include "../include/access.h"
#include "testlib.h"

#include <string.h>

static AccessPath fixture_path;
static PathComponent fixture_components[3];
static bool fail_path_resolution;
static bool fail_next_strdup;
static unsigned path_free_calls;
static PermissionResult decisions[3][3];

char *__real_strdup(const char *s);

char *__wrap_strdup(const char *s)
{
    if (fail_next_strdup)
    {
        fail_next_strdup = false;
        return NULL;
    }
    return __real_strdup(s);
}

AccessPath *path_resolve(const char *path)
{
    (void)path;
    return fail_path_resolution ? NULL : &fixture_path;
}

void path_free(AccessPath *path)
{
    (void)path; /* fixture storage is static */
    path_free_calls++;
}

PermissionResult evaluate_permissions(const User *user, const struct stat *st,
                                      AccessOperation op, acl_t acl)
{
    (void)user;
    (void)acl;
    return decisions[st->st_uid][op];
}

AccessReason mount_restriction_reason(bool flags_known, bool read_only,
                                      bool noexec, const struct stat *st,
                                      AccessOperation op)
{
    if (!flags_known || !st)
        return REASON_NONE;
    if (op == ACCESS_WRITE && read_only)
        return REASON_MOUNT_READ_ONLY;
    if (op == ACCESS_EXECUTE && S_ISREG(st->st_mode) && noexec)
        return REASON_MOUNT_NOEXEC;
    return REASON_NONE;
}

AccessReason attribute_restriction_reason(bool flags_known, bool immutable,
                                          bool append_only, AccessOperation op)
{
    if (!flags_known)
        return REASON_NONE;
    if (immutable && (op == ACCESS_WRITE || op == ACCESS_DELETE))
        return REASON_IMMUTABLE;
    if (append_only && op == ACCESS_DELETE)
        return REASON_APPEND_ONLY;
    return REASON_NONE;
}

static void setup_fixture(bool target_is_directory)
{
    memset(fixture_components, 0, sizeof(fixture_components));
    memset(decisions, 0, sizeof(decisions));
    fixture_components[0].path = "/";
    fixture_components[0].st.st_mode = S_IFDIR | 0755;
    fixture_components[0].st.st_uid = 0;
    fixture_components[1].path = "/target";
    fixture_components[1].st.st_mode = (target_is_directory ? S_IFDIR : S_IFREG) | 0755;
    fixture_components[1].st.st_uid = 1;
    fixture_path.components = fixture_components;
    fixture_path.count = 2;
    fail_path_resolution = false;
    fail_next_strdup = false;
    path_free_calls = 0;

    for (size_t i = 0; i < 2; i++)
        for (size_t op = 0; op < 3; op++)
            decisions[i][op] = (PermissionResult){
                .allowed = true, .reason = REASON_NONE,
                .source = PERMISSION_SOURCE_UNIX_OTHER,
                .entry_permissions = 7, .effective_permissions = 7,
                .mask_permissions = 7,
            };
}

static void check_path_resolution_failure(void)
{
    setup_fixture(false);
    fail_path_resolution = true;
    User user = {.name = "fixture"};
    AccessResult result = check_access(&user, "/unavailable", ACCESS_READ);
    CHECK(!result.allowed && result.reason == REASON_NOT_FOUND);
    CHECK(result.access_path == NULL && result.blocked_path == NULL);
    access_result_free(&result);
}

static void check_intermediate_traversal_block(void)
{
    setup_fixture(false);
    decisions[0][ACCESS_EXECUTE] = (PermissionResult){
        .allowed = false, .reason = REASON_OTHER_DENIED,
        .source = PERMISSION_SOURCE_UNIX_OTHER, .entry_permissions = 4,
        .effective_permissions = 4, .mask_permissions = 7,
    };
    User user = {.name = "fixture"};
    AccessResult result = check_access(&user, "/target", ACCESS_READ);
    CHECK(!result.allowed && result.reason == REASON_OTHER_DENIED);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/") == 0);
    CHECK(result.access_path->components[0].checked_permission_known);
    CHECK(!result.access_path->components[0].can_execute);
    access_result_free(&result);
}

static void check_directory_write_needs_search_then_write(void)
{
    User user = {.name = "fixture"};
    setup_fixture(true);
    decisions[1][ACCESS_EXECUTE] = (PermissionResult){
        .allowed = false, .reason = REASON_OWNER_DENIED,
        .source = PERMISSION_SOURCE_UNIX_OWNER,
    };
    AccessResult result = check_access(&user, "/target", ACCESS_WRITE);
    CHECK(!result.allowed && result.blocked_on_traversal);
    CHECK(result.reason == REASON_OWNER_DENIED);
    access_result_free(&result);

    setup_fixture(true);
    decisions[1][ACCESS_WRITE] = (PermissionResult){
        .allowed = false, .reason = REASON_GROUP_DENIED,
        .source = PERMISSION_SOURCE_UNIX_GROUP,
    };
    result = check_access(&user, "/target", ACCESS_WRITE);
    CHECK(!result.allowed && !result.blocked_on_traversal);
    CHECK(result.reason == REASON_GROUP_DENIED);
    access_result_free(&result);
}

static void check_mount_restrictions_override_dac_allow(void)
{
    User user = {.name = "fixture"};
    setup_fixture(false);
    fixture_components[1].mount_flags_known = true;
    fixture_components[1].mount_noexec = true;
    AccessResult result = check_access(&user, "/target", ACCESS_EXECUTE);
    CHECK(!result.allowed && result.reason == REASON_MOUNT_NOEXEC);
    CHECK(result.access_path->components[1].checked_permission.source == PERMISSION_SOURCE_MOUNT);
    access_result_free(&result);

    setup_fixture(true);
    fixture_components[1].mount_flags_known = true;
    fixture_components[1].mount_read_only = true;
    result = check_access(&user, "/target", ACCESS_WRITE);
    CHECK(!result.allowed && result.reason == REASON_MOUNT_READ_ONLY);
    CHECK(result.access_path->components[1].checked_permission.source == PERMISSION_SOURCE_MOUNT);
    access_result_free(&result);
}

static void check_strdup_failure_never_returns_allowed(void)
{
    User user = {.name = "fixture"};

    /* A path inspection failure needs strdup() to preserve blocked_path. If
       that allocation fails, check_access must not fall through to "allowed"
       with a freed AccessPath. */
    setup_fixture(false);
    fixture_components[1].denial_reason = REASON_BROKEN_SYMLINK;
    fail_next_strdup = true;
    AccessResult result = check_access(&user, "/target", ACCESS_READ);
    CHECK(!result.allowed);
    CHECK(result.reason == REASON_NOT_FOUND);
    CHECK(result.access_path == NULL && result.blocked_path == NULL);
    CHECK(path_free_calls == 1);
    access_result_free(&result);

    /* The same allocation failure can happen after a DAC denial. */
    setup_fixture(false);
    decisions[1][ACCESS_READ] = (PermissionResult){
        .allowed = false, .reason = REASON_OWNER_DENIED,
        .source = PERMISSION_SOURCE_UNIX_OWNER,
    };
    fail_next_strdup = true;
    result = check_access(&user, "/target", ACCESS_READ);
    CHECK(!result.allowed);
    CHECK(result.reason == REASON_NOT_FOUND);
    CHECK(result.access_path == NULL && result.blocked_path == NULL);
    CHECK(path_free_calls == 1);
    access_result_free(&result);
}

static void check_path_inspection_error_is_reported_before_dac(void)
{
    setup_fixture(false);
    fixture_components[1].denial_reason = REASON_BROKEN_SYMLINK;
    User user = {.name = "fixture"};
    AccessResult result = check_access(&user, "/target", ACCESS_READ);
    CHECK(!result.allowed && result.reason == REASON_BROKEN_SYMLINK);
    CHECK(result.access_path->components[1].checked_permission_known == false);
    access_result_free(&result);
}

/* delete walks the parent chain and then applies the sticky-bit ownership rule.
   These cases drive every branch of that logic deterministically through the
   mocked path/permission layer, including the ones a real filesystem cannot
   produce on demand (an empty resolved path, a NULL entry name, a read-only
   mount, and an allocation failure mid-denial). */
static void check_delete_logic(void)
{
    User user = {.name = "fixture"};

    /* Defensive: an empty resolved path is reported as not-found. */
    setup_fixture(false);
    fixture_path.count = 0;
    AccessResult result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_NOT_FOUND);
    access_result_free(&result);

    /* The ".." entry cannot be removed. */
    setup_fixture(false);
    fixture_components[1].path = "/..";
    result = check_access(&user, "/..", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_DELETE_SPECIAL);
    access_result_free(&result);

    /* A trailing slash on the entry name is stripped before the . / .. test;
       the name is ordinary, so a writable non-sticky parent allows removal. */
    setup_fixture(false);
    fixture_components[1].path = "/entry/";
    fixture_components[1].link_st_known = true;
    result = check_access(&user, "/entry/", ACCESS_DELETE);
    CHECK(result.allowed);
    access_result_free(&result);

    /* Defensive: a NULL entry name is tolerated by the . / .. test. */
    setup_fixture(false);
    fixture_components[1].path = NULL;
    fixture_components[1].link_st_known = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(result.allowed);
    access_result_free(&result);

    /* A component flagged during resolution short-circuits the walk and is the
       reported blocker, before any permission is evaluated on it. */
    setup_fixture(false);
    fixture_components[1].path = "/mid";
    fixture_components[1].st.st_mode = S_IFDIR | 0755;
    fixture_components[1].st.st_uid = 0;
    fixture_components[1].denial_reason = REASON_BROKEN_SYMLINK;
    fixture_components[2].path = "/mid/target";
    fixture_components[2].st.st_mode = S_IFREG | 0755;
    fixture_components[2].st.st_uid = 0;
    fixture_path.count = 3;
    result = check_access(&user, "/mid/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_BROKEN_SYMLINK);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/mid") == 0);
    access_result_free(&result);

    /* A read-only mount on the parent blocks removal even when DAC allows it. */
    setup_fixture(false);
    fixture_components[0].mount_flags_known = true;
    fixture_components[0].mount_read_only = true;
    fixture_components[1].link_st_known = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_MOUNT_READ_ONLY);
    access_result_free(&result);

    /* Sticky parent, user owns neither entry nor directory: denied. If the
       allocation that records the blocked path fails, the result degrades to
       not-found and frees the path rather than reporting a bogus "allowed". */
    setup_fixture(false);
    fixture_components[0].st.st_mode = S_IFDIR | 0755 | S_ISVTX;
    fixture_components[1].link_st_known = true;
    fixture_components[1].link_st.st_uid = 1;
    user.uid = 5;
    fail_next_strdup = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_NOT_FOUND);
    CHECK(result.access_path == NULL && result.blocked_path == NULL);
    CHECK(path_free_calls == 1);
    access_result_free(&result);

    /* Sticky parent, but root is exempt from the ownership restriction. */
    setup_fixture(false);
    fixture_components[0].st.st_mode = S_IFDIR | 0755 | S_ISVTX;
    fixture_components[1].link_st_known = true;
    fixture_components[1].link_st.st_uid = 1;
    user.uid = 0;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(result.allowed);
    access_result_free(&result);

    /* Sticky parent, but the user owns the entry: allowed. */
    setup_fixture(false);
    fixture_components[0].st.st_mode = S_IFDIR | 0755 | S_ISVTX;
    fixture_components[1].link_st_known = true;
    fixture_components[1].link_st.st_uid = 1;
    user.uid = 1;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(result.allowed);
    access_result_free(&result);

    /* Sticky parent, but the user owns the directory: allowed. The parent is
       owned by a non-root uid, so permissions for it must be granted too. */
    setup_fixture(false);
    for (size_t op = 0; op < 3; op++)
        decisions[2][op] = decisions[0][op];
    fixture_components[0].st.st_mode = S_IFDIR | 0755 | S_ISVTX;
    fixture_components[0].st.st_uid = 2;
    fixture_components[1].link_st_known = true;
    fixture_components[1].link_st.st_uid = 1;
    user.uid = 2;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(result.allowed);
    access_result_free(&result);
}

/* Immutable and append-only inode attributes override DAC on the target and,
   for deletion, on the parent directory. They sit after the mount check in both
   check_access and check_delete; these cases drive each attribute branch. */
static void check_attribute_restrictions(void)
{
    User user = {.name = "fixture", .uid = 1};

    /* Immutable file blocks write even when DAC would allow it. */
    setup_fixture(false);
    fixture_components[1].attr_flags_known = true;
    fixture_components[1].attr_immutable = true;
    AccessResult result = check_access(&user, "/target", ACCESS_WRITE);
    CHECK(!result.allowed && result.reason == REASON_IMMUTABLE);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/target") == 0);
    CHECK(result.access_path->components[1].checked_permission.source ==
          PERMISSION_SOURCE_FS_ATTR);
    access_result_free(&result);

    /* Immutable does not touch reads: the file stays readable. */
    setup_fixture(false);
    fixture_components[1].attr_flags_known = true;
    fixture_components[1].attr_immutable = true;
    result = check_access(&user, "/target", ACCESS_READ);
    CHECK(result.allowed);
    access_result_free(&result);

    /* Append-only still permits writes (they must append), so write is allowed. */
    setup_fixture(false);
    fixture_components[1].attr_flags_known = true;
    fixture_components[1].attr_append_only = true;
    result = check_access(&user, "/target", ACCESS_WRITE);
    CHECK(result.allowed);
    access_result_free(&result);

    /* An immutable parent directory refuses removal of any entry. */
    setup_fixture(false);
    fixture_components[0].attr_flags_known = true;
    fixture_components[0].attr_immutable = true;
    fixture_components[1].link_st_known = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_IMMUTABLE);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/") == 0);
    CHECK(result.access_path->components[0].checked_permission.source ==
          PERMISSION_SOURCE_FS_ATTR);
    access_result_free(&result);

    /* An append-only parent directory refuses removal too. */
    setup_fixture(false);
    fixture_components[0].attr_flags_known = true;
    fixture_components[0].attr_append_only = true;
    fixture_components[1].link_st_known = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_APPEND_ONLY);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/") == 0);
    access_result_free(&result);

    /* An immutable target cannot be unlinked, even with a writable parent. */
    setup_fixture(false);
    fixture_components[1].link_st_known = true;
    fixture_components[1].attr_flags_known = true;
    fixture_components[1].attr_immutable = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_IMMUTABLE);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/target") == 0);
    CHECK(result.access_path->components[1].checked_permission.source ==
          PERMISSION_SOURCE_FS_ATTR);
    access_result_free(&result);

    /* An append-only target cannot be unlinked either. */
    setup_fixture(false);
    fixture_components[1].link_st_known = true;
    fixture_components[1].attr_flags_known = true;
    fixture_components[1].attr_append_only = true;
    result = check_access(&user, "/target", ACCESS_DELETE);
    CHECK(!result.allowed && result.reason == REASON_APPEND_ONLY);
    CHECK(result.blocked_path && strcmp(result.blocked_path, "/target") == 0);
    access_result_free(&result);
}

int main(void)
{
    check_path_resolution_failure();
    check_intermediate_traversal_block();
    check_directory_write_needs_search_then_write();
    check_mount_restrictions_override_dac_allow();
    check_path_inspection_error_is_reported_before_dac();
    check_strdup_failure_never_returns_allowed();
    check_delete_logic();
    check_attribute_restrictions();
    return TEST_SUMMARY();
}
