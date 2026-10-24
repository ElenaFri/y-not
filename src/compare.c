#include "compare.h"

#include <stdlib.h>
#include <string.h>

/* The tokens already consumed sit in [start, current): each had its trailing
   comma overwritten with '\0' as it was processed, so they form a run of
   NUL-terminated strings we can walk to spot a repeat of `tok`. */
static bool token_seen_before(const char *start, const char *current,
                              const char *tok)
{
    for (const char *prior = start; prior < current; prior += strlen(prior) + 1)
        if (strcmp(prior, tok) == 0)
            return true;
    return false;
}

static char *allowed_account_name(const char *name, const char *path,
                                  AccessOperation operation)
{
    User *u = user_lookup(name);
    if (!u)
        return NULL;

    char *allowed = NULL;
    AccessResult r = check_access(u, path, operation);
    if (r.allowed)
        allowed = strdup(u->name);
    access_result_free(&r);
    user_free(u);
    return allowed;
}

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
    if (!allowed)
    {
        free(work);
        return NULL;
    }

    size_t count = 0;
    const char *cursor = work;
    while (cursor)
    {
        char *delimiter = strchr(cursor, ',');
        if (delimiter)
            *delimiter = '\0';

        const char *tok = cursor;
        bool skip = *tok == '\0' || strcmp(tok, primary) == 0 ||
                    token_seen_before(work, cursor, tok);

        if (!skip && count < cap)
        {
            char *name = allowed_account_name(tok, path, operation);
            if (name)
                allowed[count++] = name;
        }

        cursor = delimiter ? delimiter + 1 : NULL;
    }
    free(work);
    *out_count = count;
    return allowed;
}
