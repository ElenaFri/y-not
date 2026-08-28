#include "access.h"
#include "output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s USER OPERATION PATH\n", prog);
    fprintf(stderr, "  OPERATION: read|r  write|w  execute|x\n");
}

static AccessOperation parse_operation(const char *s)
{
    if (strcmp(s, "read") == 0 || strcmp(s, "r") == 0)
        return ACCESS_READ;
    if (strcmp(s, "write") == 0 || strcmp(s, "w") == 0)
        return ACCESS_WRITE;
    if (strcmp(s, "execute") == 0 || strcmp(s, "x") == 0)
        return ACCESS_EXECUTE;
    fprintf(stderr, "Unknown operation: %s\n", s);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *username = argv[1];
    AccessOperation operation = parse_operation(argv[2]);
    const char *path = argv[3];

    User *user = user_lookup(username);
    if (!user)
    {
        fprintf(stderr, "y-not: user not found: %s\n", username);
        return EXIT_FAILURE;
    }

    AccessResult result = check_access(user, path, operation);
    render_result_text(&result, operation);

    int exit_code = result.allowed ? EXIT_SUCCESS : EXIT_FAILURE;
    access_result_free(&result);
    user_free(user);
    return exit_code;
}
