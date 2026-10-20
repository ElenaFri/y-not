#include "../include/permissions/permissions.h"
#include "testlib.h"

#include <errno.h>

static int fail_tag_call;
static int fail_permset_call;
static int tag_calls;
static int permset_calls;

int __real_acl_get_tag_type(acl_entry_t entry, acl_tag_t *tag);
int __real_acl_get_permset(acl_entry_t entry, acl_permset_t *permset);

int __wrap_acl_get_tag_type(acl_entry_t entry, acl_tag_t *tag)
{
    tag_calls++;
    if (tag_calls == fail_tag_call)
    {
        errno = EINVAL;
        return -1;
    }
    return __real_acl_get_tag_type(entry, tag);
}

int __wrap_acl_get_permset(acl_entry_t entry, acl_permset_t *permset)
{
    permset_calls++;
    if (permset_calls == fail_permset_call)
    {
        errno = EINVAL;
        return -1;
    }
    return __real_acl_get_permset(entry, permset);
}

static User make_user(uid_t uid, gid_t primary, gid_t *groups, size_t n)
{
    return (User){.uid = uid, .primary_gid = primary, .groups = groups, .group_count = n, .name = "test"};
}

static struct stat make_stat(uid_t uid, gid_t gid, mode_t mode)
{
    struct stat st = {0};
    st.st_uid = uid;
    st.st_gid = gid;
    st.st_mode = S_IFREG | mode;
    return st;
}

int main(void)
{
    gid_t root_g[] = {0};
    gid_t alice_g[] = {1000, 1001}; /* 1001 = devs */
    gid_t carol_g[] = {1003, 1001}; /* supplementary = devs */
    gid_t bob_g[] = {1002};         /* unrelated group */

    User root = make_user(0, 0, root_g, 1);
    User alice = make_user(1000, 1000, alice_g, 2);
    User bob = make_user(1002, 1002, bob_g, 1);
    User carol = make_user(1003, 1003, carol_g, 2);

    struct stat st_644 = make_stat(1000, 1001, 0644);
    struct stat st_640 = make_stat(1000, 1001, 0640);
    struct stat st_600 = make_stat(1000, 1001, 0600);
    struct stat st_200 = make_stat(1000, 1001, 0200);

    PermissionResult r;

    /* Root bypasses DAC; executing a regular file still requires an x bit,
       while directory search is bypassed even when no x bit is set. */
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_READ, NULL).allowed);
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_WRITE, NULL).allowed);
    CHECK(!evaluate_permissions(&root, &st_644, ACCESS_EXECUTE, NULL).allowed);
    struct stat st_755 = make_stat(1000, 1001, 0755);
    CHECK(evaluate_permissions(&root, &st_755, ACCESS_EXECUTE, NULL).allowed);
    struct stat dir_no_x = {0};
    dir_no_x.st_mode = S_IFDIR | 0000;
    CHECK(evaluate_permissions(&root, &dir_no_x, ACCESS_EXECUTE, NULL).allowed);
    CHECK(!evaluate_permissions(&alice, &dir_no_x, ACCESS_EXECUTE, NULL).allowed);

    struct stat st_directory = {0};
    st_directory.st_mode = S_IFDIR | 0777;
    CHECK(mount_restriction_reason(false, true, true, &st_644, ACCESS_WRITE) == REASON_NONE);
    CHECK(mount_restriction_reason(true, true, false, &st_644, ACCESS_WRITE) == REASON_MOUNT_READ_ONLY);
    CHECK(mount_restriction_reason(true, true, false, &st_directory, ACCESS_WRITE) == REASON_MOUNT_READ_ONLY);
    CHECK(mount_restriction_reason(true, false, true, &st_644, ACCESS_EXECUTE) == REASON_MOUNT_NOEXEC);
    CHECK(mount_restriction_reason(true, false, true, &st_directory, ACCESS_EXECUTE) == REASON_NONE);
    CHECK(mount_restriction_reason(true, true, true, &st_644, ACCESS_READ) == REASON_NONE);
    CHECK(mount_restriction_reason(true, false, false, NULL, ACCESS_READ) == REASON_NONE);

    /* alice is owner - 0644: r+w ok, x denied */
    CHECK(evaluate_permissions(&alice, &st_644, ACCESS_READ, NULL).allowed);
    CHECK(evaluate_permissions(&alice, &st_644, ACCESS_WRITE, NULL).allowed);
    r = evaluate_permissions(&alice, &st_644, ACCESS_EXECUTE, NULL);
    CHECK(!r.allowed && r.reason == REASON_OWNER_DENIED);

    /* alice is owner - 0200: read denied */
    r = evaluate_permissions(&alice, &st_200, ACCESS_READ, NULL);
    CHECK(!r.allowed && r.reason == REASON_OWNER_DENIED);

    /* carol in group via supplementary group - 0640: read ok */
    CHECK(evaluate_permissions(&carol, &st_640, ACCESS_READ, NULL).allowed);

    /* carol in group - write denied (group has no w on 0640) */
    r = evaluate_permissions(&carol, &st_640, ACCESS_WRITE, NULL);
    CHECK(!r.allowed && r.reason == REASON_GROUP_DENIED);

    /* bob not in group - other allows read on 0644 */
    CHECK(evaluate_permissions(&bob, &st_644, ACCESS_READ, NULL).allowed);

    /* bob not in group - other cannot read 0640, but group could */
    r = evaluate_permissions(&bob, &st_640, ACCESS_READ, NULL);
    CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
    CHECK(r.missing_group_known && r.missing_group_gid == 1001);

    /* bob not in group - 0600: neither other nor group help */
    r = evaluate_permissions(&bob, &st_600, ACCESS_READ, NULL);
    CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);

    /* ---- ACL tests (evaluate_acl) ---- */
    /*
     * File: owner uid=999, group gid=1002, mode=640.
     * alice (uid=1000) and carol (uid=1003) are neither the owner
     * nor in group 1002: the named-ACL path is exercised for them.
     */
    gid_t acl_alice_g[] = {1000};
    gid_t acl_carol_g[] = {1003, 1001}; /* 1001 = devs */
    User acl_alice = make_user(1000, 1000, acl_alice_g, 1);
    User acl_carol = make_user(1003, 1003, acl_carol_g, 2);
    User acl_owner = make_user(999, 1002, NULL, 0);
    User acl_stranger = make_user(7000, 7000, NULL, 0);
    struct stat st_acl = make_stat(999, 1002, 0640);

    /* ACL_USER_OBJ: the file owner is evaluated through the ACL, not mode bits */
    acl_t acl0 = acl_from_text("user::rw-,group::---,mask::r--,other::---");
    CHECK(acl0 != NULL);
    if (acl0)
    {
        r = evaluate_permissions(&acl_owner, &st_acl, ACCESS_READ, acl0);
        CHECK(r.allowed && r.reason == REASON_NONE);
        r = evaluate_permissions(&acl_owner, &st_acl, ACCESS_EXECUTE, acl0);
        CHECK(!r.allowed && r.reason == REASON_OWNER_DENIED);
        acl_free(acl0);
    }

    /* ACL_USER: alice gets read through a named entry */
    acl_t acl1 = acl_from_text("user::rw-,user:1000:r--,group::---,mask::r--,other::---");
    CHECK(acl1 != NULL);
    if (acl1)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_READ, acl1);
        CHECK(r.allowed && r.reason == REASON_NONE);

        /* The mode mask has read set, but no group ACL entry actually grants
           it. Do not infer a hypothetical grant from stat()'s group bits. */
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ, acl1);
        CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);

        acl_free(acl1);
    }

    /* ACL_USER + mask: alice has rw in the entry but the mask caps it to read */
    acl_t acl2 = acl_from_text("user::rw-,user:1000:rw-,group::---,mask::r--,other::---");
    CHECK(acl2 != NULL);
    if (acl2)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_READ, acl2);
        CHECK(r.allowed);
        CHECK(r.source == PERMISSION_SOURCE_ACL_USER);
        CHECK(r.entry_permissions == 6 && r.effective_permissions == 4);
        CHECK(r.mask_applied && r.mask_permissions == 4);
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_WRITE, acl2);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        CHECK(r.source == PERMISSION_SOURCE_ACL_USER);
        CHECK(r.entry_permissions == 6 && r.effective_permissions == 4);
        acl_free(acl2);
    }

    /* ACL_USER is decisive: alice has ---, other has r-- but the denial wins */
    acl_t acl3 = acl_from_text("user::rw-,user:1000:---,group::---,mask::r--,other::r--");
    CHECK(acl3 != NULL);
    if (acl3)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_READ, acl3);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        acl_free(acl3);
    }

    /* ACL_GROUP: carol is in group 1001 (devs), which has read */
    acl_t acl4 = acl_from_text("user::rw-,group::---,group:1001:r--,mask::r--,other::---");
    CHECK(acl4 != NULL);
    if (acl4)
    {
        r = evaluate_permissions(&acl_carol, &st_acl, ACCESS_READ, acl4);
        CHECK(r.allowed && r.reason == REASON_NONE);
        r = evaluate_permissions(&acl_carol, &st_acl, ACCESS_WRITE, acl4);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);

        /* ACL_OTHER: a stranger with no matching entry falls through to other */
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_WRITE, acl4);
        CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);
        acl_free(acl4);
    }

    /* libacl can fail while reading an ACL entry (for example, allocation
       failure in qualifier lookup). The evaluator skips that entry and keeps
       processing rather than using uninitialized tag/permission data. */
    acl_t acl_read_failure = acl_from_text(
        "user::rw-,group::---,group:2001:r--,mask::r--,other::---");
    CHECK(acl_read_failure != NULL);
    if (acl_read_failure)
    {
        tag_calls = 0;
        fail_tag_call = 1;
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_read_failure);
        fail_tag_call = 0;
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 2001);

        permset_calls = 0;
        fail_permset_call = 1;
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_read_failure);
        fail_permset_call = 0;
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 2001);

        /* Five entries are read in the main pass; fail the first tag lookup
           in candidate collection to exercise its independent error path. */
        tag_calls = 0;
        fail_tag_call = 6;
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_read_failure);
        fail_tag_call = 0;
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 2001);
        acl_free(acl_read_failure);
    }

    /* An unmatched ACL group that would grant access explains the denial
       as missing group membership, not as a generic "other" denial. */
    acl_t acl_group_missing = acl_from_text(
        "user::rw-,group::---,group:2001:r--,mask::r--,other::---");
    CHECK(acl_group_missing != NULL);
    if (acl_group_missing)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_group_missing);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.source == PERMISSION_SOURCE_ACL_OTHER);
        CHECK(r.missing_group_known && r.missing_group_gid == 2001);
        acl_free(acl_group_missing);
    }

    /* The owning group ACL entry is also a possible missing membership. */
    acl_t acl_group_obj_missing = acl_from_text(
        "user::rw-,group::r--,mask::r--,other::---");
    CHECK(acl_group_obj_missing != NULL);
    if (acl_group_obj_missing)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_group_obj_missing);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.missing_group_known && r.missing_group_gid == 1002);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 1002);
        acl_free(acl_group_obj_missing);
    }

    /* Several groups could grant the operation: the owning group and two named
       group entries. All three are reported as candidate memberships, in ACL
       order, and missing_group_gid mirrors the first. */
    acl_t acl_multi_missing = acl_from_text(
        "user::rw-,group::r--,group:2001:r--,group:2002:r--,mask::r--,other::---");
    CHECK(acl_multi_missing != NULL);
    if (acl_multi_missing)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_multi_missing);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 3);
        CHECK(r.candidate_group_gids[0] == 1002);
        CHECK(r.candidate_group_gids[1] == 2001);
        CHECK(r.candidate_group_gids[2] == 2002);
        CHECK(r.missing_group_known && r.missing_group_gid == 1002);
        acl_free(acl_multi_missing);
    }

    /* Only groups whose effective rights survive the mask are candidates: here
       2002's read is removed by the mask, so just 2001 is reported. */
    acl_t acl_multi_masked = acl_from_text(
        "user::rw-,group::---,group:2001:r--,group:2002:-w-,mask::r--,other::---");
    CHECK(acl_multi_masked != NULL);
    if (acl_multi_masked)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_multi_masked);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 2001);
        acl_free(acl_multi_masked);
    }

    /* A plain mode-bits denial reports exactly the owning group as the single
       candidate membership. */
    r = evaluate_permissions(&bob, &st_640, ACCESS_READ, NULL);
    CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
    CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 1001);

    /* A named group entry duplicating the owning group's gid is reported once. */
    acl_t acl_dup_group = acl_from_text(
        "user::rw-,group::r--,group:1002:r--,mask::r--,other::---");
    CHECK(acl_dup_group != NULL);
    if (acl_dup_group)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_dup_group);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 1002);
        acl_free(acl_dup_group);
    }

    /* More granting groups than the candidate array holds: the list is capped
       at Y_NOT_MAX_CANDIDATE_GROUPS without overflowing. */
    {
        char text[1024];
        size_t len = (size_t)snprintf(text, sizeof(text),
            "user::rw-,group::---,mask::r--,other::---");
        for (int g = 3000; g < 3000 + Y_NOT_MAX_CANDIDATE_GROUPS + 4; g++)
            len += (size_t)snprintf(text + len, sizeof(text) - len,
                                    ",group:%d:r--", g);
        acl_t acl_many = acl_from_text(text);
        CHECK(acl_many != NULL);
        if (acl_many)
        {
            r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                     acl_many);
            CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
            CHECK(r.candidate_group_count == Y_NOT_MAX_CANDIDATE_GROUPS);
            acl_free(acl_many);
        }
    }

    /* A group entry's raw read bit does not imply a possible grant when the
       ACL mask removes it; that is an "other" denial, not missing membership. */
    acl_t acl_group_masked = acl_from_text(
        "user::rw-,group::r--,group:2001:---,mask::---,other::---");
    CHECK(acl_group_masked != NULL);
    if (acl_group_masked)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_group_masked);
        CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);
        CHECK(!r.missing_group_known);
        acl_free(acl_group_masked);
    }

    /* Candidate collection uses the requested operation bit, not just read.
       Both groups survive the write mask and can independently grant write. */
    acl_t acl_write_candidates = acl_from_text(
        "user::rw-,group::---,group:2101:-w-,group:2102:-w-,mask::-w-,other::---");
    CHECK(acl_write_candidates != NULL);
    if (acl_write_candidates)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_WRITE,
                                 acl_write_candidates);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 2);
        CHECK(r.candidate_group_gids[0] == 2101);
        CHECK(r.candidate_group_gids[1] == 2102);
        acl_free(acl_write_candidates);
    }

    /* A minimal ACL without an explicit mask defaults to rwx. */
    acl_t acl_without_mask = acl_from_text(
        "user::rw-,group::r--,other::---");
    CHECK(acl_without_mask != NULL);
    if (acl_without_mask)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_without_mask);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        CHECK(r.candidate_group_count == 1 && r.candidate_group_gids[0] == 1002);
        CHECK(!r.mask_applied && r.mask_permissions == 7);
        acl_free(acl_without_mask);
    }

    /* Execute permission is also subject to the ACL mask, both when granted
       and when denied. */
    acl_t acl_execute = acl_from_text(
        "user::rw-,user:1000:rwx,group::---,mask::rwx,other::---");
    CHECK(acl_execute != NULL);
    if (acl_execute)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_EXECUTE,
                                 acl_execute);
        CHECK(r.allowed && r.reason == REASON_NONE);
        CHECK(r.entry_permissions == 7 && r.effective_permissions == 7);
        CHECK(r.mask_applied && r.mask_permissions == 7);
        acl_free(acl_execute);
    }

    /* ACL_GROUP_OBJ: a member of the file's own owning group (gid 1002),
       granted directly (not through a named group entry). */
    User acl_owning_group = make_user(5000, 1002, NULL, 0);
    acl_t acl4b = acl_from_text("user::rw-,group::r--,mask::r--,other::---");
    CHECK(acl4b != NULL);
    if (acl4b)
    {
        r = evaluate_permissions(&acl_owning_group, &st_acl, ACCESS_READ, acl4b);
        CHECK(r.allowed && r.reason == REASON_NONE);
        acl_free(acl4b);
    }

    /* ACL_GROUP: matching multiple named groups is a logical OR, not an AND -
       a single granting entry is enough even if another one denies. */
    gid_t dave_g[] = {2001, 2002};
    User acl_dave = make_user(4000, 4000, dave_g, 2);

    acl_t acl6 = acl_from_text("user::rw-,group::---,group:2001:---,group:2002:r--,mask::r--,other::---");
    CHECK(acl6 != NULL);
    if (acl6)
    {
        r = evaluate_permissions(&acl_dave, &st_acl, ACCESS_READ, acl6);
        CHECK(r.allowed && r.reason == REASON_NONE);
        acl_free(acl6);
    }

    /* Named group entries apply the execute mask and report the same
       membership distinction for execute as for read/write. */
    acl_t acl_group_execute = acl_from_text(
        "user::rw-,group::---,group:2001:--x,mask::--x,other::---");
    CHECK(acl_group_execute != NULL);
    if (acl_group_execute)
    {
        r = evaluate_permissions(&acl_dave, &st_acl, ACCESS_EXECUTE,
                                 acl_group_execute);
        CHECK(r.allowed && r.source == PERMISSION_SOURCE_ACL_GROUP);
        CHECK(r.entry_permissions == 1 && r.effective_permissions == 1);
        CHECK(r.mask_applied && r.mask_permissions == 1);
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_EXECUTE,
                                 acl_group_execute);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        acl_free(acl_group_execute);
    }

    acl_t acl_group_write_missing = acl_from_text(
        "user::rw-,group::---,group:2001:-w-,mask::-w-,other::---");
    CHECK(acl_group_write_missing != NULL);
    if (acl_group_write_missing)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_WRITE,
                                 acl_group_write_missing);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);
        acl_free(acl_group_write_missing);
    }

    acl_t acl_other_execute = acl_from_text(
        "user::rw-,group::---,mask::---,other::--x");
    CHECK(acl_other_execute != NULL);
    if (acl_other_execute)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_EXECUTE,
                                 acl_other_execute);
        CHECK(r.allowed && r.source == PERMISSION_SOURCE_ACL_OTHER);
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ,
                                 acl_other_execute);
        CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);
        acl_free(acl_other_execute);
    }

    /* ...but if every matching group entry denies, the result is still denied. */
    acl_t acl7 = acl_from_text("user::rw-,group::---,group:2001:---,group:2002:---,mask::r--,other::---");
    CHECK(acl7 != NULL);
    if (acl7)
    {
        r = evaluate_permissions(&acl_dave, &st_acl, ACCESS_READ, acl7);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        acl_free(acl7);
    }

    /* mask denying EXECUTE specifically (previous tests only masked read/write) */
    acl_t acl8 = acl_from_text("user::rw-,user:1000:rwx,group::---,mask::rw-,other::---");
    CHECK(acl8 != NULL);
    if (acl8)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_EXECUTE, acl8);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        acl_free(acl8);
    }

    /* ACL_GROUP grants the raw bit, but the mask still caps it down to denied */
    acl_t acl9 = acl_from_text("user::rw-,group::---,group:2001:rw-,mask::r--,other::---");
    CHECK(acl9 != NULL);
    if (acl9)
    {
        r = evaluate_permissions(&acl_dave, &st_acl, ACCESS_WRITE, acl9);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        acl_free(acl9);
    }

    /* ACL_OTHER actually granting access (previous other-path tests only denied) */
    acl_t acl10 = acl_from_text("user::rw-,group::---,mask::r--,other::r--");
    CHECK(acl10 != NULL);
    if (acl10)
    {
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ, acl10);
        CHECK(r.allowed && r.reason == REASON_NONE);
        acl_free(acl10);
    }

    /* root always bypasses ACLs, same as plain mode bits */
    acl_t acl5 = acl_from_text("user::---,group::---,mask::---,other::---");
    CHECK(acl5 != NULL);
    if (acl5)
    {
        CHECK(evaluate_permissions(&root, &st_acl, ACCESS_READ, acl5).allowed);
        acl_free(acl5);
    }

    return TEST_SUMMARY();
}
