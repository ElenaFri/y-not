#include "../include/context/mac_warning.h"
#include "testlib.h"

#include <string.h>

static void check_evaluate_selinux(void)
{
    /* Enforcing SELinux can turn an allow into a deny: flag it. */
    MacWarning w = mac_warning_evaluate(
        true, (SelinuxStatus){.available = true, .enforcing = 1}, (ApparmorStatus){0});
    CHECK(w.selinux_enforcing == true);
    CHECK(w.apparmor_active == false);
    CHECK(w.may_override_verdict == true);

    /* Permissive SELinux never denies: no override possible. */
    w = mac_warning_evaluate(
        true, (SelinuxStatus){.available = true, .enforcing = 0}, (ApparmorStatus){0});
    CHECK(w.selinux_enforcing == false);
    CHECK(w.may_override_verdict == false);

    /* SELinux not enabled at all. */
    w = mac_warning_evaluate(
        true, (SelinuxStatus){.available = false, .enforcing = -1}, (ApparmorStatus){0});
    CHECK(w.selinux_enforcing == false);
    CHECK(w.may_override_verdict == false);
}

static void check_evaluate_apparmor(void)
{
    /* Profiles loaded: a confined program may be denied. */
    MacWarning w = mac_warning_evaluate(
        true, (SelinuxStatus){0}, (ApparmorStatus){.available = true, .profile_count = 7});
    CHECK(w.apparmor_active == true);
    CHECK(w.may_override_verdict == true);

    /* Enabled but zero profiles: nothing is confined. */
    w = mac_warning_evaluate(
        true, (SelinuxStatus){0}, (ApparmorStatus){.available = true, .profile_count = 0});
    CHECK(w.apparmor_active == false);
    CHECK(w.may_override_verdict == false);

    /* Unknown count (needs privilege to read): warn conservatively. */
    w = mac_warning_evaluate(
        true, (SelinuxStatus){0}, (ApparmorStatus){.available = true, .profile_count = -1});
    CHECK(w.apparmor_active == true);
    CHECK(w.may_override_verdict == true);

    /* AppArmor not enabled. */
    w = mac_warning_evaluate(
        true, (SelinuxStatus){0}, (ApparmorStatus){.available = false, .profile_count = -1});
    CHECK(w.apparmor_active == false);
    CHECK(w.may_override_verdict == false);
}

static void check_evaluate_denied_is_never_flagged(void)
{
    /* Even with both modules active, a denial already holds (DAC before MAC). */
    MacWarning w = mac_warning_evaluate(
        false, (SelinuxStatus){.available = true, .enforcing = 1},
        (ApparmorStatus){.available = true, .profile_count = 3});
    CHECK(w.selinux_enforcing == true);
    CHECK(w.apparmor_active == true);
    CHECK(w.may_override_verdict == false);
}

static void check_message_names_the_active_modules(void)
{
    char buf[256];

    MacWarning both = mac_warning_evaluate(
        true, (SelinuxStatus){.available = true, .enforcing = 1},
        (ApparmorStatus){.available = true, .profile_count = 2});
    mac_warning_message(both, buf, sizeof(buf));
    CHECK(strstr(buf, "SELinux is enforcing") != NULL);
    CHECK(strstr(buf, "AppArmor is active") != NULL);
    CHECK(strstr(buf, "does not evaluate mandatory access control") != NULL);

    MacWarning se = mac_warning_evaluate(
        true, (SelinuxStatus){.available = true, .enforcing = 1}, (ApparmorStatus){0});
    mac_warning_message(se, buf, sizeof(buf));
    CHECK(strstr(buf, "SELinux is enforcing") != NULL);
    CHECK(strstr(buf, "AppArmor") == NULL);

    MacWarning aa = mac_warning_evaluate(
        true, (SelinuxStatus){0}, (ApparmorStatus){.available = true, .profile_count = 1});
    mac_warning_message(aa, buf, sizeof(buf));
    CHECK(strstr(buf, "AppArmor is active") != NULL);
    CHECK(strstr(buf, "SELinux") == NULL);
}

static void check_message_empty_when_not_warranted(void)
{
    char buf[256];
    MacWarning none = mac_warning_evaluate(true, (SelinuxStatus){0}, (ApparmorStatus){0});
    mac_warning_message(none, buf, sizeof(buf));
    CHECK(buf[0] == '\0');

    /* A zero-size buffer must be handled without writing anything. */
    char tiny[1] = {'x'};
    MacWarning active = mac_warning_evaluate(
        true, (SelinuxStatus){.available = true, .enforcing = 1}, (ApparmorStatus){0});
    const char *ret = mac_warning_message(active, tiny, 0);
    CHECK(ret == tiny);
    CHECK(tiny[0] == 'x'); /* untouched */
}

int main(void)
{
    check_evaluate_selinux();
    check_evaluate_apparmor();
    check_evaluate_denied_is_never_flagged();
    check_message_names_the_active_modules();
    check_message_empty_when_not_warranted();
    return TEST_SUMMARY();
}
