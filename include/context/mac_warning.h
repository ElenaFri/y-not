#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "context/apparmor_info.h"
#include "context/selinux_info.h"

typedef struct
{
    bool selinux_enforcing;    /* SELinux is enabled and in enforcing mode */
    bool apparmor_active;      /* AppArmor is enabled with loaded (or possibly
                                  loaded) profiles */
    bool may_override_verdict; /* an allowed DAC/ACL verdict could still be
                                  overridden by an active MAC module */
} MacWarning;

/* Decide whether an allowed DAC/ACL verdict might be overridden by an active
   mandatory access control (MAC) module. Pure: every input is explicit, so it
   is unit-testable without a MAC-enabled host.

   A denied verdict is never flagged: the kernel checks DAC before any security
   module, so a DAC/ACL denial already holds regardless of SELinux or AppArmor.
   Only an *allowed* verdict is at risk of being wrong on a confined system. */
MacWarning mac_warning_evaluate(bool allowed, SelinuxStatus selinux, ApparmorStatus apparmor);

/* Write a one-line, human-readable warning into buf (always NUL-terminated).
   Only meaningful when warning.may_override_verdict is true; writes an empty
   string otherwise. Returns buf. */
const char *mac_warning_message(MacWarning warning, char *buf, size_t size);
