#pragma once

#include <stdbool.h>
#include "resolve/user.h"

/* Whether the user would have CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH
   available via /etc/security/capability.conf (pam_cap). These are the
   only two capabilities that affect discretionary file permission checks;
   CAP_DAC_OVERRIDE bypasses read/write/execute (like root), while
   CAP_DAC_READ_SEARCH only bypasses read and directory traversal. */
bool user_has_dac_override(const User *user);
bool user_has_dac_read_search(const User *user);

/* Exposed for testing: same lookup, against an arbitrary config file
   instead of the real /etc/security/capability.conf. Returns false if the
   file does not exist. Implements the documented first-matching-line-wins
   semantics of capability.conf(5), but only tracks whether "cap_name" is
   granted (bare or "^" ambient) or explicitly dropped ("!") - it does not
   simulate the full inheritable/ambient/bounding (IAB) capability model. */
bool capability_conf_grants(const char *config_path, const User *user,
                            const char *cap_name);
