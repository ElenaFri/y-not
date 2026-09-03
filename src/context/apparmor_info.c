#include "context/apparmor_info.h"

#include <stdio.h>

#define APPARMOR_ENABLED_PATH "/sys/module/apparmor/parameters/enabled"
#define APPARMOR_PROFILES_PATH "/sys/kernel/security/apparmor/profiles"

ApparmorStatus apparmor_status_from(const char *enabled_path, const char *profiles_path)
{
    ApparmorStatus s = {.available = false, .profile_count = -1};

    FILE *f = fopen(enabled_path, "r");
    if (!f)
        return s;
    int c = fgetc(f);
    fclose(f);
    if (c != 'Y' && c != 'y')
        return s;
    s.available = true;

    f = fopen(profiles_path, "r");
    if (!f)
        return s; /* profile_count stays -1: commonly needs elevated privilege */

    int count = 0;
    while ((c = fgetc(f)) != EOF)
        if (c == '\n')
            count++;
    fclose(f);
    s.profile_count = count;
    return s;
}

ApparmorStatus apparmor_status(void)
{
    return apparmor_status_from(APPARMOR_ENABLED_PATH, APPARMOR_PROFILES_PATH);
}
