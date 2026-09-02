#pragma once

#include <stdbool.h>

typedef struct
{
    bool available;    /* AppArmor module loaded and enabled */
    int profile_count; /* number of loaded profiles; -1 if unreadable */
} ApparmorStatus;

/* Purely informational: y-not does not check whether a specific profile
   would restrict access to a given path, since AppArmor confines programs,
   not users - a check that would need a 4th "which program" argument. */
ApparmorStatus apparmor_status(void);

/* Exposed for testing: same logic against arbitrary files instead of the
   real /sys/module/apparmor/parameters/enabled and
   /sys/kernel/security/apparmor/profiles (the latter commonly requires
   elevated privilege to read, even when its own mode bits look world-
   readable - profile_count is -1 in that case, not 0). */
ApparmorStatus apparmor_status_from(const char *enabled_path, const char *profiles_path);
