#include "../include/context/selinux_info.h"
#include "testlib.h"

#include <selinux/selinux.h>
#include <stdlib.h>
#include <string.h>

static int enabled;
static int enforcing;
static int getfilecon_result;
static const char *context_value;
static unsigned getfilecon_calls;
static const char *last_requested_path;

int is_selinux_enabled(void)
{
    return enabled;
}

int security_getenforce(void)
{
    return enforcing;
}

int getfilecon(const char *path, char **context)
{
    getfilecon_calls++;
    last_requested_path = path;
    if (getfilecon_result < 0)
    {
        *context = NULL;
        return -1;
    }
    if (!context_value)
    {
        *context = NULL;
        return 0;
    }
    *context = strdup(context_value);
    return *context ? (int)strlen(*context) : -1;
}

void freecon(char *context)
{
    free(context);
}

int main(void)
{
    const char *test_path = "mocked/context-target";
    enabled = 0;
    SelinuxStatus status = selinux_status();
    CHECK(!status.available && status.enforcing == -1);
    unsigned calls_before = getfilecon_calls;
    CHECK(selinux_file_context(test_path) == NULL);
    CHECK(getfilecon_calls == calls_before); /* disabled: no label lookup */

    enabled = 1;
    enforcing = 1;
    status = selinux_status();
    CHECK(status.available && status.enforcing == 1);

    enforcing = 0;
    status = selinux_status();
    CHECK(status.available && status.enforcing == 0);

    enforcing = -1; /* status is enabled even if the enforcing query fails */
    status = selinux_status();
    CHECK(status.available && status.enforcing == -1);

    context_value = "system_u:object_r:tmp_t:s0";
    getfilecon_result = 0;
    char *context = selinux_file_context(test_path);
    CHECK(context != NULL && strcmp(context, context_value) == 0);
    CHECK(context != context_value); /* returned storage is owned by caller */
    CHECK(strcmp(last_requested_path, test_path) == 0);
    free(context);

    getfilecon_result = -1;
    CHECK(selinux_file_context(test_path) == NULL);

    getfilecon_result = 0;
    context_value = NULL;
    CHECK(selinux_file_context(test_path) == NULL);

    return TEST_SUMMARY();
}
