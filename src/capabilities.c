#include "capabilities.h"

#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "mode_bits.h"

#define CAPABILITY_CONF_PATH "/etc/security/capability.conf"

static bool who_matches(const char *who, const User *user)
{
    if (strcmp(who, "*") == 0)
        return true;
    if (who[0] == '@')
    {
        const struct group *gr = getgrnam(who + 1);
        return gr && user_in_group(user, gr->gr_gid);
    }
    return strcmp(who, user->name) == 0;
}

/* Returns 1 = granted, 0 = explicitly dropped ("!"), -1 = not mentioned. */
static int cap_term_verdict(const char *iab_spec, const char *cap_name)
{
    if (strcasecmp(iab_spec, "all") == 0)
        return 1;
    if (strcasecmp(iab_spec, "none") == 0)
        return -1;

    char *copy = strdup(iab_spec);
    if (!copy)
        return -1;

    int verdict = -1;
    char *saveptr = NULL;
    for (char *term = strtok_r(copy, ",", &saveptr); term;
         term = strtok_r(NULL, ",", &saveptr))
    {
        bool negated = (*term == '!');
        const char *name = (*term == '!' || *term == '^') ? term + 1 : term;
        if (strcasecmp(name, cap_name) == 0)
        {
            verdict = negated ? 0 : 1;
            break;
        }
    }
    free(copy);
    return verdict;
}

bool capability_conf_grants(const char *config_path, const User *user,
                            const char *cap_name)
{
    FILE *f = fopen(config_path, "r");
    if (!f)
        return false;

    char *line = NULL;
    size_t linesize = 0;
    bool result = false;

    while (getline(&line, &linesize, f) != -1)
    {
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;

        char *saveptr = NULL;
        char *iab_spec = strtok_r(p, " \t\r\n", &saveptr);
        if (!iab_spec)
            continue;

        bool matched_line = false;
        for (char *who = strtok_r(NULL, " \t\r\n", &saveptr); who;
             who = strtok_r(NULL, " \t\r\n", &saveptr))
        {
            if (who_matches(who, user))
            {
                matched_line = true;
                break;
            }
        }

        if (matched_line)
        {
            result = (cap_term_verdict(iab_spec, cap_name) == 1);
            break; /* capability.conf(5): first matching line wins */
        }
    }

    free(line);
    fclose(f);
    return result;
}

bool user_has_dac_override(const User *user)
{
    return capability_conf_grants(CAPABILITY_CONF_PATH, user, "cap_dac_override");
}

bool user_has_dac_read_search(const User *user)
{
    return capability_conf_grants(CAPABILITY_CONF_PATH, user, "cap_dac_read_search");
}
