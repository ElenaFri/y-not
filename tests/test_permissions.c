#include "../include/permissions.h"
#include "testlib.h"

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

    /* root: always allowed, except execute with no x bit anywhere */
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_READ, NULL).allowed);
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_WRITE, NULL).allowed);
    CHECK(!evaluate_permissions(&root, &st_644, ACCESS_EXECUTE, NULL).allowed);
    struct stat st_755 = make_stat(1000, 1001, 0755);
    CHECK(evaluate_permissions(&root, &st_755, ACCESS_EXECUTE, NULL).allowed);

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

        /* a stranger falls through to ACL_OTHER (denied here); since the
           file's group-class mode bits (0640 = group r--) would have
           allowed it, the reason must say GROUP_MISSING, not OTHER_DENIED -
           the same nuance as the non-ACL path, but never exercised through
           evaluate_acl() until now. */
        r = evaluate_permissions(&acl_stranger, &st_acl, ACCESS_READ, acl1);
        CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);

        acl_free(acl1);
    }

    /* ACL_USER + mask: alice has rw in the entry but the mask caps it to read */
    acl_t acl2 = acl_from_text("user::rw-,user:1000:rw-,group::---,mask::r--,other::---");
    CHECK(acl2 != NULL);
    if (acl2)
    {
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_READ, acl2);
        CHECK(r.allowed);
        r = evaluate_permissions(&acl_alice, &st_acl, ACCESS_WRITE, acl2);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
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

    /* ...but if every matching group entry denies, the result is still denied. */
    acl_t acl7 = acl_from_text("user::rw-,group::---,group:2001:---,group:2002:---,mask::r--,other::---");
    CHECK(acl7 != NULL);
    if (acl7)
    {
        r = evaluate_permissions(&acl_dave, &st_acl, ACCESS_READ, acl7);
        CHECK(!r.allowed && r.reason == REASON_ACL_DENIED);
        acl_free(acl7);
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
