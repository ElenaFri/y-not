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
    if (!allowed)
    {
        free(work);
        return NULL;
    }

    size_t count = 0;
    char *tok = work;
    while (tok)
    {
        char *delimiter = strchr(tok, ',');
        if (delimiter)
            *delimiter = '\0';

        bool duplicate = false;
        size_t token_offset = (size_t)(tok - work);
        size_t token_length = strlen(tok);
        for (const char *prior = list; prior < list + token_offset;)
        {
            const char *prior_end = strchr(prior, ',');
            if (!prior_end || prior_end > list + token_offset)
                prior_end = list + token_offset;
            size_t prior_length = (size_t)(prior_end - prior);
            if (prior_length == token_length &&
                memcmp(prior, tok, prior_length) == 0)
            {
                duplicate = true;
                break;
            }
            prior = prior_end + 1;
        }

        if (*tok != '\0' && strcmp(tok, primary) != 0 && !duplicate)
        {
            User *u = user_lookup(tok);
            if (u)
            {
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
        }

        tok = delimiter ? delimiter + 1 : NULL;
    }
    free(work);
    *out_count = count;
    return allowed;
}
