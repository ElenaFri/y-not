#include "selinux_info.h"

#include <selinux/selinux.h>
#include <stdlib.h>
#include <string.h>

SelinuxStatus selinux_status(void)
{
    SelinuxStatus s = {.available = false, .enforcing = -1};
    if (is_selinux_enabled() == 1)
    {
        s.available = true;
        s.enforcing = security_getenforce();
    }
    return s;
}

char *selinux_file_context(const char *path)
{
    if (is_selinux_enabled() != 1)
        return NULL;

    char *con = NULL;
    if (getfilecon(path, &con) < 0 || !con)
        return NULL;

    char *owned = strdup(con);
    freecon(con);
    return owned;
}
