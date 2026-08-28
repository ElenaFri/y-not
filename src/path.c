#include "path.h"

#include <stdlib.h>

AccessPath *path_resolve(const char *path)
{
    (void)path;
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
