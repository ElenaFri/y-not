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

    /* root: toujours autorisé sauf exécution sans aucun bit x */
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_READ).allowed);
    CHECK(evaluate_permissions(&root, &st_644, ACCESS_WRITE).allowed);
    CHECK(!evaluate_permissions(&root, &st_644, ACCESS_EXECUTE).allowed);
    struct stat st_755 = make_stat(1000, 1001, 0755);
    CHECK(evaluate_permissions(&root, &st_755, ACCESS_EXECUTE).allowed);

    /* alice est owner — 0644: r+w ok, x refusé */
    CHECK(evaluate_permissions(&alice, &st_644, ACCESS_READ).allowed);
    CHECK(evaluate_permissions(&alice, &st_644, ACCESS_WRITE).allowed);
    r = evaluate_permissions(&alice, &st_644, ACCESS_EXECUTE);
    CHECK(!r.allowed && r.reason == REASON_OWNER_DENIED);

    /* alice est owner — 0200: lecture refusée */
    r = evaluate_permissions(&alice, &st_200, ACCESS_READ);
    CHECK(!r.allowed && r.reason == REASON_OWNER_DENIED);

    /* carol dans le groupe via groupe supplémentaire — 0640: lecture ok */
    CHECK(evaluate_permissions(&carol, &st_640, ACCESS_READ).allowed);

    /* carol dans le groupe — écriture refusée (groupe n'a pas w sur 0640) */
    r = evaluate_permissions(&carol, &st_640, ACCESS_WRITE);
    CHECK(!r.allowed && r.reason == REASON_GROUP_DENIED);

    /* bob pas dans le groupe — other permet lecture sur 0644 */
    CHECK(evaluate_permissions(&bob, &st_644, ACCESS_READ).allowed);

    /* bob pas dans le groupe — other ne peut pas lire 0640, mais groupe oui */
    r = evaluate_permissions(&bob, &st_640, ACCESS_READ);
    CHECK(!r.allowed && r.reason == REASON_GROUP_MISSING);

    /* bob pas dans le groupe — 0600: ni other ni groupe n'aident */
    r = evaluate_permissions(&bob, &st_600, ACCESS_READ);
    CHECK(!r.allowed && r.reason == REASON_OTHER_DENIED);

    return TEST_SUMMARY();
}
