#include "access.h"
#include "output.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef Y_NOT_VERSION
#define Y_NOT_VERSION "0.0.0-dev"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out, "Usage: %s USER OPERATION PATH\n", prog);
    fprintf(out, "       %s --help | --version\n", prog);
    fprintf(out, "  OPERATION: read|r  write|w  execute|x\n");
}

static void help(const char *prog)
{
    printf("y-not - explain why a user can or cannot access a file or directory\n\n");
    usage(stdout, prog);
    printf("\n");
    printf("  USER       an existing Unix user name\n");
    printf("  PATH       an absolute or relative filesystem path\n\n");
    printf("Exit status: 0 if access is allowed, 1 if denied or an error occurred.\n");
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
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0))
    {
        help(argv[0]);
        return EXIT_SUCCESS;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0)
    {
        printf("y-not %s\n", Y_NOT_VERSION);
        return EXIT_SUCCESS;
    }

    if (argc != 4)
    {
        usage(stderr, argv[0]);
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
    render_result_text(&result, user, operation);

    int exit_code = result.allowed ? EXIT_SUCCESS : EXIT_FAILURE;
    access_result_free(&result);
    user_free(user);
    return exit_code;
}
