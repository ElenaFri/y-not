#include "../include/permissions/mode_bits.h"
#include "testlib.h"

int main(void)
{
    mode_t mode = S_IFREG | 0741;

    CHECK(class_allows(mode, ACCESS_READ, 6));
    CHECK(class_allows(mode, ACCESS_WRITE, 6));
    CHECK(class_allows(mode, ACCESS_EXECUTE, 6));
    CHECK(class_allows(mode, ACCESS_READ, 3));
    CHECK(!class_allows(mode, ACCESS_WRITE, 3));
    CHECK(!class_allows(mode, ACCESS_EXECUTE, 3));
    CHECK(!class_allows(mode, ACCESS_READ, 0));
    CHECK(!class_allows(mode, ACCESS_WRITE, 0));
    CHECK(class_allows(mode, ACCESS_EXECUTE, 0));
    CHECK(!class_allows(mode, (AccessOperation)999, 6));

    gid_t supplementary[] = {20, 30};
    User user = {.uid = 1000, .primary_gid = 10,
                 .groups = supplementary, .group_count = 2, .name = "test"};
    CHECK(user_in_group(&user, 10));
    CHECK(user_in_group(&user, 20));
    CHECK(user_in_group(&user, 30));
    CHECK(!user_in_group(&user, 40));

    User no_supplementary = {.uid = 1001, .primary_gid = 11,
                             .groups = NULL, .group_count = 0, .name = "empty"};
    CHECK(user_in_group(&no_supplementary, 11));
    CHECK(!user_in_group(&no_supplementary, 20));

    return TEST_SUMMARY();
}
