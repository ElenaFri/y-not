#include "access.h"
#include "compare.h"
#include "render/json_output.h"
#include "render/output.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef Y_NOT_VERSION
#define Y_NOT_VERSION "0.0.0-dev"
#endif

static void usage(FILE *out, const char *prog)
{
    fprintf(out, "Usage: %s [--json] USER OPERATION PATH [--compare USER,USER,...]\n", prog);
    fprintf(out, "       %s --help | --version\n", prog);
    fprintf(out, "  OPERATION: read|r  write|w  execute|x  delete|d\n");
}

static void help(const char *prog)
{
    printf("y-not - explain why a user can or cannot access a file or directory\n\n");
    usage(stdout, prog);
    printf("\n");
    printf("  --json     emit a JSON document instead of human-readable text\n");
    printf("  --compare  also report which of the listed accounts are allowed\n");
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
    if (strcmp(s, "delete") == 0 || strcmp(s, "d") == 0)
        return ACCESS_DELETE;
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

    /* --json must come first: keeps parsing a simple, fixed-position check
       rather than a full flag parser, matching the rest of this CLI. */
    bool json = (argc >= 5 && strcmp(argv[1], "--json") == 0);

    /* argc with just the three positionals; also the index at which an
       optional "--compare LIST" (two more tokens) would begin. */
    int after = json ? 5 : 4;

    bool compare = false;
    const char *compare_list = NULL;
    if (argc == after + 2 && strcmp(argv[after], "--compare") == 0)
    {
        compare = true;
        compare_list = argv[after + 1];
    }
    else if (argc != after)
    {
        usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }

    const char *username = argv[json ? 2 : 1];
    AccessOperation operation = parse_operation(argv[json ? 3 : 2]);
    const char *path = argv[json ? 4 : 3];

    User *user = user_lookup(username);
    if (!user)
    {
        if (json)
            render_user_not_found_json(username, operation, path);
        else
            fprintf(stderr, "y-not: user not found: %s\n", username);
        return EXIT_FAILURE;
    }

    AccessResult result = check_access(user, path, operation);

    ComparedUsers compared = {0};
    char **allowed_names = NULL;
    if (compare)
    {
        compared.requested = true;
        allowed_names = compare_allowed_accounts(compare_list, username, path, operation,
                                                 &compared.allowed_count);
        compared.allowed = (const char *const *)allowed_names;
    }

    if (json)
        render_result_json(&result, username, operation, path, &compared);
    else
        render_result_text(&result, user, operation, &compared);

    if (allowed_names)
    {
        for (size_t i = 0; i < compared.allowed_count; i++)
            free(allowed_names[i]);
        free(allowed_names);
    }

    int exit_code = result.allowed ? EXIT_SUCCESS : EXIT_FAILURE;
    access_result_free(&result);
    user_free(user);
    return exit_code;
}
