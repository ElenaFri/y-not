#include "path.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void stat_component(PathComponent *c)
{
    if (stat(c->path, &c->st) != -1)
        return;
    c->denial_reason = (errno == ENOENT || errno == ENOTDIR)
                           ? REASON_NOT_FOUND
                           : REASON_NOT_TRAVERSABLE;
}

AccessPath *path_resolve(const char *input)
{
    if (!input)
        return NULL;

    char abs[PATH_MAX];
    size_t ilen = strlen(input);

    if (*input == '/')
    {
        if (ilen >= sizeof(abs))
            return NULL;
        memcpy(abs, input, ilen + 1);
    }
    else
    {
        if (!getcwd(abs, sizeof(abs)))
            return NULL;
        size_t clen = strlen(abs);
        if (clen + 1 + ilen >= sizeof(abs))
            return NULL;
        abs[clen] = '/';
        memcpy(abs + clen + 1, input, ilen + 1);
    }

    size_t len = strlen(abs);
    while (len > 1 && abs[len - 1] == '/')
        abs[--len] = '\0';

    /* one component per '/' plus one for the last segment */
    size_t count = 1;
    for (size_t i = 1; i < len; i++)
        if (abs[i] == '/')
            count++;
    if (len > 1)
        count++;

    AccessPath *ap = malloc(sizeof(*ap));
    if (!ap)
        return NULL;
    ap->components = calloc(count, sizeof(PathComponent));
    if (!ap->components)
    {
        free(ap);
        return NULL;
    }
    ap->count = count;

    size_t ci = 0;
    ap->components[ci].path = strdup("/");
    if (!ap->components[ci].path)
        goto err;
    stat_component(&ap->components[ci++]);

    for (size_t i = 1; len > 1 && i < len; i++)
    {
        if (abs[i] == '/')
        {
            ap->components[ci].path = strndup(abs, i);
            if (!ap->components[ci].path)
                goto err;
            stat_component(&ap->components[ci++]);
        }
    }

    if (len > 1)
    {
        ap->components[ci].path = strdup(abs);
        if (!ap->components[ci].path)
            goto err;
        stat_component(&ap->components[ci]);
    }

    return ap;

err:
    path_free(ap);
    return NULL;
}

void path_free(AccessPath *ap)
{
    if (!ap)
        return;
    for (size_t i = 0; i < ap->count; i++)
        free(ap->components[i].path);
    free(ap->components);
    free(ap);
}
