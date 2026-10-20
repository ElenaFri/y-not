#include "context/mac_warning.h"

#include <stdio.h>

MacWarning mac_warning_evaluate(bool allowed, SelinuxStatus selinux, ApparmorStatus apparmor)
{
    MacWarning w = {0};
    w.selinux_enforcing = selinux.available && selinux.enforcing == 1;
    /* profile_count: >0 loaded, 0 none, -1 unknown (reading the list needs
       privilege). Treat "unknown" as possibly-active so y-not never under-warns
       on a confined host it simply could not inspect. */
    w.apparmor_active = apparmor.available && apparmor.profile_count != 0;
    w.may_override_verdict = allowed && (w.selinux_enforcing || w.apparmor_active);
    return w;
}

const char *mac_warning_message(MacWarning warning, char *buf, size_t size)
{
    if (size == 0)
        return buf;
    if (!warning.may_override_verdict)
    {
        buf[0] = '\0';
        return buf;
    }

    const char *subject;
    if (warning.selinux_enforcing && warning.apparmor_active)
        subject = "SELinux is enforcing and AppArmor is active";
    else if (warning.selinux_enforcing)
        subject = "SELinux is enforcing";
    else
        subject = "AppArmor is active";

    snprintf(buf, size,
             "this verdict covers DAC/ACL only; %s on this system, and y-not "
             "does not evaluate mandatory access control, so the kernel may "
             "still deny access",
             subject);
    return buf;
}
