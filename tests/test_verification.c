#include "../include/verify/verification.h"
#include "../include/resolve/user.h"
#include "testlib.h"

#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------- verification_classify: pure, exhaustively covered ---------- */

static KernelProbe probe_of(KernelProbeVerdict verdict, const char *reason)
{
    KernelProbe p = {verdict, reason};
    return p;
}

/* An unavailable probe never becomes a verdict: it reports NOT_PROBED and
   carries the probe's own reason through unchanged. */
static void check_unavailable_probe_is_not_probed(void)
{
    Verification v =
        verification_classify(false, probe_of(KERNEL_PROBE_UNAVAILABLE, "no root"));
    CHECK(v.status == VERIFICATION_NOT_PROBED);
    CHECK(v.detail != NULL && strcmp(v.detail, "no root") == 0);
}

/* Agreement in either direction is CONFIRMED, with nothing to add. */
static void check_agreement_is_confirmed(void)
{
    Verification allow =
        verification_classify(true, probe_of(KERNEL_PROBE_ALLOWED, NULL));
    CHECK(allow.status == VERIFICATION_CONFIRMED);
    CHECK(allow.kernel_allowed);
    CHECK(allow.detail == NULL);

    Verification deny =
        verification_classify(false, probe_of(KERNEL_PROBE_DENIED, NULL));
    CHECK(deny.status == VERIFICATION_CONFIRMED);
    CHECK(!deny.kernel_allowed);
    CHECK(deny.detail == NULL);
}

/* Model says allowed, kernel denies: the selling case. The sentence must point
   at a security module as the likely cause. */
static void check_model_allow_kernel_deny_blames_mac(void)
{
    Verification v =
        verification_classify(true, probe_of(KERNEL_PROBE_DENIED, NULL));
    CHECK(v.status == VERIFICATION_DIVERGENT);
    CHECK(!v.kernel_allowed);
    CHECK(v.detail != NULL && strstr(v.detail, "SELinux") != NULL);
}

/* Model says denied, kernel allows: a gap in y-not's own modeling, to report. */
static void check_model_deny_kernel_allow_is_modeling_gap(void)
{
    Verification v =
        verification_classify(false, probe_of(KERNEL_PROBE_ALLOWED, NULL));
    CHECK(v.status == VERIFICATION_DIVERGENT);
    CHECK(v.kernel_allowed);
    CHECK(v.detail != NULL && strstr(v.detail, "modeling gap") != NULL);
}

/* ---------- verification_evaluate: skipped reasons never probe ---------- */

/* Evaluate a denial for `reason` without any real path: the skip decision is
   taken before the probe, so the (unused) user and path are placeholders. */
static Verification evaluate_denial(AccessReason reason)
{
    User dummy = {.uid = 0, .primary_gid = 0, .groups = NULL,
                  .group_count = 0, .name = NULL};
    AccessResult result = {.allowed = false, .reason = reason,
                           .blocked_path = NULL, .blocked_on_traversal = false,
                           .access_path = NULL};
    return verification_evaluate(&result, &dummy, "/anything", ACCESS_READ);
}

static void check_attribute_and_sticky_denials_are_skipped(void)
{
    const AccessReason reasons[] = {REASON_IMMUTABLE, REASON_APPEND_ONLY,
                                    REASON_STICKY_BIT};
    for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; i++)
    {
        Verification v = evaluate_denial(reasons[i]);
        CHECK(v.status == VERIFICATION_NOT_PROBED);
        CHECK(v.detail != NULL && strstr(v.detail, "inode attribute") != NULL);
    }
}

static void check_unresolved_path_is_skipped(void)
{
    Verification v = evaluate_denial(REASON_NOT_FOUND);
    CHECK(v.status == VERIFICATION_NOT_PROBED);
    CHECK(v.detail != NULL && strstr(v.detail, "could not be resolved") != NULL);
}

static void check_untraversable_path_is_skipped(void)
{
    const AccessReason reasons[] = {REASON_NOT_TRAVERSABLE, REASON_BROKEN_SYMLINK,
                                    REASON_SYMLINK_LOOP};
    for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; i++)
    {
        Verification v = evaluate_denial(reasons[i]);
        CHECK(v.status == VERIFICATION_NOT_PROBED);
        CHECK(v.detail != NULL && strstr(v.detail, "could not traverse") != NULL);
    }
}

static void check_delete_special_denials_are_skipped(void)
{
    const AccessReason reasons[] = {REASON_DELETE_ROOT, REASON_DELETE_SPECIAL};
    for (size_t i = 0; i < sizeof reasons / sizeof reasons[0]; i++)
    {
        Verification v = evaluate_denial(reasons[i]);
        CHECK(v.status == VERIFICATION_NOT_PROBED);
        CHECK(v.detail != NULL && strstr(v.detail, "delete has no kernel") != NULL);
    }
}

/* ---------- verification_evaluate: the real-probe path ---------- */

/* A User standing in for the account running the tests, with its real
   supplementary groups. Returns NULL only if lookup fails, so the caller skips. */
static User *current_user(void)
{
    struct passwd pwd;
    struct passwd *result = NULL;
    char storage[1024];
    if (getpwuid_r(getuid(), &pwd, storage, sizeof storage, &result) != 0 ||
        !result)
        return NULL;
    return user_lookup(pwd.pw_name);
}

/* Create a traversable temp directory with a regular file of `mode` inside. */
static bool make_file(char *dir, size_t dir_size, char *file, size_t file_size,
                      mode_t mode)
{
    snprintf(dir, dir_size, "%s/y_not_verify_test_XXXXXX", P_tmpdir);
    if (!mkdtemp(dir))
        return false;
    snprintf(file, file_size, "%s/target", dir);
    FILE *f = fopen(file, "w");
    if (!f)
        return false;
    fclose(f);
    return chmod(file, mode) == 0 && chmod(dir, 0700) == 0;
}

static void cleanup_file(const char *dir, const char *file)
{
    unlink(file);
    rmdir(dir);
}

/* Model and kernel agree on a readable file we own: CONFIRMED, nothing to add.
   access_path is NULL, so the original path is probed. */
static void check_confirmed_when_model_and_kernel_agree(void)
{
    User *me = current_user();
    if (!me)
        return;
    char dir[256];
    char file[sizeof(dir) + 16];
    if (!make_file(dir, sizeof dir, file, sizeof file, 0644))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    AccessResult result = {.allowed = true, .reason = REASON_NONE,
                           .blocked_path = NULL, .blocked_on_traversal = false,
                           .access_path = NULL};
    Verification v = verification_evaluate(&result, me, file, ACCESS_READ);
    CHECK(v.status == VERIFICATION_CONFIRMED);
    CHECK(v.kernel_allowed);
    CHECK(v.detail == NULL);

    cleanup_file(dir, file);
    user_free(me);
}

/* Model (wrongly) denies a readable file we own: the kernel allows it, so the
   result is DIVERGENT and flagged as a modeling gap. access_path is populated,
   so the resolved last component is the probed path. */
static void check_divergent_when_model_denies_readable_file(void)
{
    User *me = current_user();
    if (!me)
        return;
    char dir[256];
    char file[sizeof(dir) + 16];
    if (!make_file(dir, sizeof dir, file, sizeof file, 0644))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    PathComponent comp = {.path = file};
    AccessPath ap = {.components = &comp, .count = 1};
    AccessResult result = {.allowed = false, .reason = REASON_OTHER_DENIED,
                           .blocked_path = NULL, .blocked_on_traversal = false,
                           .access_path = &ap};
    Verification v = verification_evaluate(&result, me, file, ACCESS_READ);
    CHECK(v.status == VERIFICATION_DIVERGENT);
    CHECK(v.kernel_allowed);
    CHECK(v.detail != NULL && strstr(v.detail, "modeling gap") != NULL);

    cleanup_file(dir, file);
    user_free(me);
}

/* An access_path that carries no components falls back to the original path. */
static void check_empty_access_path_falls_back_to_path(void)
{
    User *me = current_user();
    if (!me)
        return;
    char dir[256];
    char file[sizeof(dir) + 16];
    if (!make_file(dir, sizeof dir, file, sizeof file, 0644))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    AccessPath ap = {.components = NULL, .count = 0};
    AccessResult result = {.allowed = true, .reason = REASON_NONE,
                           .blocked_path = NULL, .blocked_on_traversal = false,
                           .access_path = &ap};
    Verification v = verification_evaluate(&result, me, file, ACCESS_READ);
    CHECK(v.status == VERIFICATION_CONFIRMED);

    cleanup_file(dir, file);
    user_free(me);
}

/* delete is not expressible via access(2): even an allowed delete is honestly
   reported as not probed, not silently confirmed. */
static void check_allowed_delete_is_not_probed(void)
{
    User *me = current_user();
    if (!me)
        return;
    char dir[256];
    char file[sizeof(dir) + 16];
    if (!make_file(dir, sizeof dir, file, sizeof file, 0644))
    {
        CHECK(false);
        user_free(me);
        return;
    }

    AccessResult result = {.allowed = true, .reason = REASON_NONE,
                           .blocked_path = NULL, .blocked_on_traversal = false,
                           .access_path = NULL};
    Verification v = verification_evaluate(&result, me, file, ACCESS_DELETE);
    CHECK(v.status == VERIFICATION_NOT_PROBED);
    CHECK(v.detail != NULL && strstr(v.detail, "delete has no kernel") != NULL);

    cleanup_file(dir, file);
    user_free(me);
}

int main(void)
{
    check_unavailable_probe_is_not_probed();
    check_agreement_is_confirmed();
    check_model_allow_kernel_deny_blames_mac();
    check_model_deny_kernel_allow_is_modeling_gap();
    check_attribute_and_sticky_denials_are_skipped();
    check_unresolved_path_is_skipped();
    check_untraversable_path_is_skipped();
    check_delete_special_denials_are_skipped();
    check_confirmed_when_model_and_kernel_agree();
    check_divergent_when_model_denies_readable_file();
    check_empty_access_path_falls_back_to_path();
    check_allowed_delete_is_not_probed();
    return TEST_SUMMARY();
}
