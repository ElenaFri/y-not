#pragma once

#include <stdbool.h>

typedef struct
{
    bool available; /* SELinux enabled on this system */
    int enforcing;  /* 1 = enforcing, 0 = permissive; meaningless if !available */
} SelinuxStatus;

/* Whether SELinux is enabled, and its current mode. Purely informational:
   y-not does not attempt to simulate the policy engine's verdict. */
SelinuxStatus selinux_status(void);

/* The file's SELinux security context (e.g. "unconfined_u:object_r:..."),
   or NULL if SELinux is unavailable or the file carries no label.
   Caller owns the returned string and must free() it. */
char *selinux_file_context(const char *path);
