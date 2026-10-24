#include "compare.h"

#include <stdlib.h>
#include <string.h>

char **compare_allowed_accounts(const char *list, const char *primary,
                                const char *path, AccessOperation operation,
                                size_t *out_count)
{
    *out_count = 0;
    char *work = strdup(list);
    if (!work)
        return NULL;

    size_t cap = 1;
    for (const char *p = list; *p; p++)
        if (*p == ',')
            cap++;

    char **allowed = calloc(cap, sizeof(char *));
    char **seen = calloc(cap, sizeof(char *));
    if (!allowed || !seen)
    {
        free(allowed);
        free(seen);
        free(work);
        return NULL;
    }

    size_t count = 0;
    size_t seen_count = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(work, ",", &saveptr); tok;
         tok = strtok_r(NULL, ",", &saveptr))
    {
        if (*tok == '\0' || strcmp(tok, primary) == 0)
            continue;

        bool already_seen = false;
        for (size_t i = 0; i < seen_count; i++)
            if (strcmp(seen[i], tok) == 0)
            {
                already_seen = true;
                break;
            }
        if (already_seen)
            continue;
        seen[seen_count++] = tok; /* points into `work`, valid until it is freed */

        User *u = user_lookup(tok);
        if (!u)
            continue;
        AccessResult r = check_access(u, path, operation);
        if (r.allowed)
        {
            char *name = strdup(u->name);
            if (name)
                allowed[count++] = name;
        }
        access_result_free(&r);
        user_free(u);
    }

    free(seen);
    free(work);
    *out_count = count;
    return allowed;
}
