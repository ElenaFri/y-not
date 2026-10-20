#include "../include/render/output.h"
#include "../include/access.h"
#include "../include/context/apparmor_info.h"
#include "../include/context/selinux_info.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <fcntl.h>
#include <grp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static SelinuxStatus mock_selinux;
static ApparmorStatus mock_apparmor;
static struct group mock_group = {.gr_name = "y_not_test_group", .gr_gid = 1234};

struct group *getgrgid(gid_t gid)
{
    return gid == mock_group.gr_gid ? &mock_group : NULL;
}

SelinuxStatus selinux_status(void)
{
    return mock_selinux;
}

ApparmorStatus apparmor_status(void)
{
    return mock_apparmor;
}

/* Most output-rendering cases exercise crash safety and formatting paths;
   selected cases capture text to assert the explanation users actually see. */
static void render_silently(const AccessResult *result, const User *user, AccessOperation op)
{
    fflush(stdout); /* flush anything buffered before fd 1 changes meaning */
    int saved = dup(STDOUT_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    close(devnull);

    render_result_text(result, user, op);

    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
}

static char *render_and_capture(const AccessResult *result, const User *user,
                                AccessOperation op)
{
    FILE *capture = tmpfile();
    if (!capture)
        return NULL;
    fflush(stdout);
    int saved = dup(STDOUT_FILENO);
    if (saved == -1 || dup2(fileno(capture), STDOUT_FILENO) == -1)
    {
        if (saved != -1)
            close(saved);
        fclose(capture);
        return NULL;
    }

    render_result_text(result, user, op);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);

    if (fseek(capture, 0, SEEK_END) != 0)
    {
        fclose(capture);
        return NULL;
    }
    long length = ftell(capture);
    if (length < 0 || fseek(capture, 0, SEEK_SET) != 0)
    {
        fclose(capture);
        return NULL;
    }
    char *text = malloc((size_t)length + 1);
    if (text)
    {
        size_t read_count = fread(text, 1, (size_t)length, capture);
        text[read_count] = '\0';
    }
    fclose(capture);
    return text;
}

/* Regression test: rendering a very deeply nested path must not overflow
   any fixed-size buffer (a stack buffer overflow was found and fixed here
   for paths with hundreds of components). */
static void check_deep_tree_does_not_crash(void)
{
    enum
    {
        DEPTH = 2000
    };

    PathComponent *comps = calloc(DEPTH, sizeof(PathComponent));
    CHECK(comps != NULL);
    if (!comps)
        return;

    for (int i = 0; i < DEPTH; i++)
    {
        char buf[16];
        snprintf(buf, sizeof(buf), "seg%d", i);
        comps[i].path = strdup(buf);
        comps[i].st.st_mode = S_IFDIR | 0755;
        comps[i].can_execute = true;
    }

    AccessPath ap = {.components = comps, .count = DEPTH};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .groups = NULL, .group_count = 0, .name = "test"};

    render_silently(&result, &user, ACCESS_READ);
    CHECK(true); /* reaching here means no crash */

    for (int i = 0; i < DEPTH; i++)
        free(comps[i].path);
    free(comps);
}

/* Regression check: when path_resolve() itself fails (NULL input, or a
   path too long to even build), check_access() returns an AccessResult
   with access_path == NULL and blocked_path == NULL. The renderer must
   handle that without dereferencing anything. */
static void check_null_access_path_does_not_crash(void)
{
    AccessResult result = {.allowed = false, .reason = REASON_NOT_FOUND, .blocked_path = NULL, .access_path = NULL};
    User user = {.uid = 1000, .primary_gid = 1000, .groups = NULL, .group_count = 0, .name = "test"};

    render_silently(&result, &user, ACCESS_READ);
    CHECK(true); /* reaching here means no crash */
}

/* Builds a 2-component tree (root + target) mirroring exactly what
   access.c produces on a real denial: both the AccessResult and the
   blocked PathComponent carry the same reason. */
static const AccessReason g_reasons[] = {
    REASON_OWNER_DENIED,
    REASON_GROUP_DENIED,
    REASON_GROUP_MISSING,
    REASON_OTHER_DENIED,
    REASON_ACL_DENIED,
    REASON_NOT_TRAVERSABLE,
    REASON_NOT_FOUND,
    REASON_BROKEN_SYMLINK,
    REASON_SYMLINK_LOOP,
    REASON_MOUNT_READ_ONLY,
    REASON_MOUNT_NOEXEC,
};

/* Every AccessReason must produce a distinct, crash-free message, and the
   blocked component must render its "(not found)"-style short form when
   applicable, or a normal permission row (marked BLOCKED) otherwise. */
static void check_every_reason_message(void)
{
    for (size_t i = 0; i < sizeof(g_reasons) / sizeof(g_reasons[0]); i++)
    {
        PathComponent comps[2] = {0};
        comps[0].path = strdup("/");
        comps[0].st.st_mode = S_IFDIR | 0755;
        comps[0].can_execute = true;

        comps[1].path = strdup("/target");
        comps[1].st.st_mode = S_IFREG | 0644;
        comps[1].st.st_uid = 999999; /* unresolvable: exercises the numeric fallback */
        comps[1].st.st_gid = 999999;
        comps[1].denial_reason = g_reasons[i];

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = false, .reason = g_reasons[i], .blocked_path = comps[1].path, .access_path = &ap};
        User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

        /* Alternate operations to exercise both display names. */
        render_silently(&result, &user, (i % 2) ? ACCESS_WRITE : ACCESS_READ);
        CHECK(true);

        free(comps[0].path);
        free(comps[1].path);
    }
}

/* file_type_char() must render every Unix file type, and a symlinked
   component must show the "name -> target" arrow form. */
static void check_file_types_and_symlink_arrow(void)
{
    const mode_t types[] = {S_IFLNK, S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK};

    for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    {
        PathComponent comps[2] = {0};
        comps[0].path = strdup("/");
        comps[0].st.st_mode = S_IFDIR | 0755;
        comps[0].can_execute = true;

        comps[1].path = strdup("/target");
        comps[1].st.st_mode = types[i] | 0644;
        comps[1].can_read = true;
        if (types[i] == S_IFLNK)
        {
            comps[1].is_symlink = true;
            comps[1].symlink_target = strdup("/elsewhere");
        }

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
        User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

        render_silently(&result, &user, ACCESS_READ);
        CHECK(true);

        free(comps[0].path);
        free(comps[1].path);
        free(comps[1].symlink_target);
    }
}

/* Optional per-component annotations (file capabilities, SELinux context)
   must be appended to the row without disturbing anything else. */
static void check_acl_decision_is_explained(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup("/report.txt");
    comps[1].st.st_mode = S_IFREG | 0640;
    comps[1].st.st_uid = 1000;
    comps[1].st.st_gid = 1000;
    comps[1].denial_reason = REASON_ACL_DENIED;
    comps[1].checked_permission_known = true;
    comps[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_ACL_DENIED,
        .source = PERMISSION_SOURCE_ACL_USER,
        .entry_permissions = 6, .effective_permissions = 4,
        .mask_permissions = 4, .mask_applied = true,
    };

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = REASON_ACL_DENIED,
                           .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 2000, .primary_gid = 2000, .name = "bob"};
    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 1};
    mock_apparmor = (ApparmorStatus){.available = true, .profile_count = 3};
    char *text = render_and_capture(&result, &user, ACCESS_WRITE);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "ACL entry found for you") != NULL);
        CHECK(strstr(text, "BLOCKED") != NULL);
        CHECK(strstr(text, "named ACL user entry: rw- & ACL mask r-- = r--") != NULL);
        CHECK(strstr(text, "SELinux: enforcing") != NULL);
        CHECK(strstr(text, "AppArmor: enabled (3 profiles loaded)") != NULL);
        free(text);
    }

    mock_selinux.enforcing = 0;
    mock_apparmor.profile_count = -1;
    text = render_and_capture(&result, &user, ACCESS_WRITE);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "SELinux: permissive") != NULL);
        CHECK(strstr(text, "profile count needs elevated privilege") != NULL);
        free(text);
    }
    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};
    free(comps[0].path);
    free(comps[1].path);
}

static void check_permission_bit_patterns_are_rendered(void)
{
    static const char *const permission_text[] = {
        "---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"};

    for (unsigned bits = 0; bits < 7; bits++)
    {
        PathComponent comps[2] = {0};
        comps[0].path = strdup("/");
        comps[0].st.st_mode = S_IFDIR | 0755;
        comps[1].path = strdup("/target");
        comps[1].st.st_mode = S_IFREG | 0640;
        comps[1].denial_reason = REASON_ACL_DENIED;
        comps[1].checked_permission_known = true;
        comps[1].checked_permission = (PermissionResult){
            .allowed = false, .reason = REASON_ACL_DENIED,
            .source = PERMISSION_SOURCE_ACL_USER,
            .entry_permissions = bits, .effective_permissions = bits,
            .mask_permissions = bits, .mask_applied = true};

        AccessPath ap = {.components = comps, .count = 2};
        AccessResult result = {.allowed = false, .reason = REASON_ACL_DENIED,
                               .blocked_path = comps[1].path, .access_path = &ap};
        User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};
        AccessOperation denied_op = !(bits & 4u) ? ACCESS_READ
                                   : !(bits & 2u) ? ACCESS_WRITE
                                                  : ACCESS_EXECUTE;
        char *text = render_and_capture(&result, &user, denied_op);
        CHECK(text != NULL);
        if (text)
        {
            char expected[128];
            snprintf(expected, sizeof(expected),
                     "named ACL user entry: %s & ACL mask %s = %s",
                     permission_text[bits], permission_text[bits],
                     permission_text[bits]);
            CHECK(strstr(text, expected) != NULL);
            free(text);
        }
        free(comps[0].path);
        free(comps[1].path);
    }
}


static void check_intermediate_traversal_explanation(void)
{
    PathComponent comps[3] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup("/private");
    comps[1].st.st_mode = S_IFDIR | 0700;
    comps[1].denial_reason = REASON_OWNER_DENIED;
    comps[1].checked_permission_known = true;
    comps[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_OWNER_DENIED,
        .source = PERMISSION_SOURCE_UNIX_OWNER};
    comps[2].path = strdup("/private/target");
    comps[2].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 3};
    AccessResult result = {.allowed = false, .reason = REASON_OWNER_DENIED,
                           .blocked_on_traversal = true,
                           .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "alice"};
    char *text = render_and_capture(&result, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "lack traverse permission") != NULL);
        CHECK(strstr(text, "enter") != NULL);
        CHECK(strstr(text, "Unix owner bits: ---") != NULL);
        free(text);
    }

    free(comps[0].path);
    free(comps[1].path);
    free(comps[2].path);
}

static void check_mount_flags_are_rendered(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0755;
    comps[1].mount_flags_known = true;
    comps[1].mount_read_only = true;
    comps[1].mount_noexec = true;
    comps[1].mount_nosuid = true;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE,
                           .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    char *text = render_and_capture(&result, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "(mount: ro noexec nosuid)") != NULL);
        free(text);
    }

    comps[1].mount_read_only = false;
    comps[1].mount_noexec = false;
    comps[1].mount_nosuid = false;
    text = render_and_capture(&result, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "(mount:") == NULL);
        free(text);
    }

    comps[1].mount_noexec = true;
    text = render_and_capture(&result, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "(mount: noexec)") != NULL);
        free(text);
    }
    comps[1].mount_noexec = false;
    comps[1].mount_nosuid = true;
    text = render_and_capture(&result, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "(mount: nosuid)") != NULL);
        free(text);
    }

    comps[1].mount_nosuid = false;
    comps[1].mount_noexec = true;
    comps[1].denial_reason = REASON_MOUNT_NOEXEC;
    comps[1].checked_permission_known = true;
    comps[1].checked_permission = (PermissionResult){
        .allowed = false, .reason = REASON_MOUNT_NOEXEC,
        .source = PERMISSION_SOURCE_MOUNT};
    result = (AccessResult){.allowed = false, .reason = REASON_MOUNT_NOEXEC,
                            .blocked_path = comps[1].path, .access_path = &ap};
    text = render_and_capture(&result, &user, ACCESS_EXECUTE);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "mount restriction: ---") != NULL);
        CHECK(strstr(text, "ACL mask") == NULL);
        free(text);
    }

    free(comps[0].path);
    free(comps[1].path);
}

static void check_file_caps_and_selinux_annotations(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0755;
    comps[1].can_execute = true;
    comps[1].file_caps = strdup("cap_net_bind_service=ep");
    comps[1].selinux_context = strdup("unconfined_u:object_r:user_home_t:s0");

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, ACCESS_EXECUTE);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
    free(comps[1].file_caps);
    free(comps[1].selinux_context);
}

/* Once the blocked component has been printed, every component after it
   is skipped (label only, no permission details) - a 2-component tree
   can never exercise that "skip" branch since the blocked one is last. */
static void check_component_after_the_blocked_one(void)
{
    PathComponent comps[3] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/blocked");
    comps[1].st.st_mode = S_IFDIR | 0755;
    comps[1].denial_reason = REASON_OWNER_DENIED;

    comps[2].path = strdup("/blocked/after");
    comps[2].st.st_mode = S_IFREG | 0644;

    AccessPath ap = {.components = comps, .count = 3};
    AccessResult result = {.allowed = false, .reason = REASON_OWNER_DENIED, .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, ACCESS_READ);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
    free(comps[2].path);
}

/* AccessOperation/AccessReason are complete enums in practice, but the
   switches have a defensive default case that should never crash if it
   were ever reached (e.g. after adding a new enum value without updating
   the renderer). */
static void check_defensive_default_cases(void)
{
    PathComponent comps[2] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_execute = true;

    comps[1].path = strdup("/target");
    comps[1].st.st_mode = S_IFREG | 0644;
    comps[1].denial_reason = (AccessReason)999;

    AccessPath ap = {.components = comps, .count = 2};
    AccessResult result = {.allowed = false, .reason = (AccessReason)999, .blocked_path = comps[1].path, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "test"};

    render_silently(&result, &user, (AccessOperation)999);
    CHECK(true);

    free(comps[0].path);
    free(comps[1].path);
}

/* MAC honesty: an "allowed" verdict under an active MAC module must carry a
   prominent warning right under the verdict, since the kernel may still deny a
   confined process. A permissive module, zero AppArmor profiles, or a denial
   must not produce one. */
static void check_mac_warning_on_allowed_verdict(void)
{
    PathComponent comps[1] = {0};
    comps[0].path = strdup("/");
    comps[0].st.st_mode = S_IFDIR | 0755;
    comps[0].can_read = true;
    AccessPath ap = {.components = comps, .count = 1};
    AccessResult allowed = {.allowed = true, .reason = REASON_NONE, .access_path = &ap};
    User user = {.uid = 1000, .primary_gid = 1000, .name = "alice"};

    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 1};
    mock_apparmor = (ApparmorStatus){0};
    char *text = render_and_capture(&allowed, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "warning") != NULL);
        CHECK(strstr(text, "SELinux is enforcing") != NULL);
        CHECK(strstr(text, "does not evaluate mandatory access control") != NULL);
        free(text);
    }

    /* Permissive SELinux cannot override an allow: no warning. */
    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 0};
    text = render_and_capture(&allowed, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "warning") == NULL);
        free(text);
    }

    /* AppArmor with loaded profiles: warning names AppArmor. */
    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){.available = true, .profile_count = 5};
    text = render_and_capture(&allowed, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "AppArmor is active") != NULL);
        free(text);
    }

    /* AppArmor enabled but zero profiles: nothing confined, no warning. */
    mock_apparmor = (ApparmorStatus){.available = true, .profile_count = 0};
    text = render_and_capture(&allowed, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "warning") == NULL);
        free(text);
    }

    /* A denial is never flagged, even with both modules active. */
    AccessResult denied = {.allowed = false, .reason = REASON_OWNER_DENIED,
                           .blocked_path = comps[0].path, .access_path = &ap};
    mock_selinux = (SelinuxStatus){.available = true, .enforcing = 1};
    mock_apparmor = (ApparmorStatus){.available = true, .profile_count = 5};
    text = render_and_capture(&denied, &user, ACCESS_READ);
    CHECK(text != NULL);
    if (text)
    {
        CHECK(strstr(text, "warning") == NULL);
        free(text);
    }

    mock_selinux = (SelinuxStatus){0};
    mock_apparmor = (ApparmorStatus){0};
    free(comps[0].path);
}

int main(void)
{
    check_deep_tree_does_not_crash();
    check_null_access_path_does_not_crash();
    check_every_reason_message();
    check_file_types_and_symlink_arrow();
    check_acl_decision_is_explained();
    check_permission_bit_patterns_are_rendered();

    check_intermediate_traversal_explanation();
    check_mount_flags_are_rendered();
    check_file_caps_and_selinux_annotations();
    check_component_after_the_blocked_one();
    check_defensive_default_cases();
    check_mac_warning_on_allowed_verdict();
    return TEST_SUMMARY();
}
