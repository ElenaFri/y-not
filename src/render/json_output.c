#include "render/json_output.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

static const char *op_name(AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:    return "read";
    case ACCESS_WRITE:   return "write";
    case ACCESS_EXECUTE: return "execute";
    default:             return "access";
    }
}

static const char *reason_code(AccessReason r)
{
    switch (r)
    {
    case REASON_NONE:            return "none";
    case REASON_OWNER_DENIED:    return "owner_denied";
    case REASON_GROUP_DENIED:    return "group_denied";
    case REASON_GROUP_MISSING:   return "group_missing";
    case REASON_OTHER_DENIED:    return "other_denied";
    case REASON_ACL_DENIED:      return "acl_denied";
    case REASON_NOT_TRAVERSABLE: return "not_traversable";
    case REASON_NOT_FOUND:       return "not_found";
    case REASON_BROKEN_SYMLINK:  return "broken_symlink";
    case REASON_SYMLINK_LOOP:    return "symlink_loop";
    default:                     return "unknown";
    }
}

static const char *file_type_name(mode_t mode)
{
    if (S_ISDIR(mode))  return "directory";
    if (S_ISLNK(mode))  return "symlink";
    if (S_ISCHR(mode))  return "character_device";
    if (S_ISBLK(mode))  return "block_device";
    if (S_ISFIFO(mode)) return "fifo";
    if (S_ISSOCK(mode)) return "socket";
    if (S_ISREG(mode))  return "file";
    return "unknown";
}

static void mode_octal(mode_t mode, char buf[6])
{
    snprintf(buf, 6, "%04o", mode & 07777);
}

static const char *uid_to_name(uid_t uid, char *buf, size_t size)
{
    const struct passwd *pw = getpwuid(uid);
    if (pw) return pw->pw_name;
    snprintf(buf, size, "%u", (unsigned)uid);
    return buf;
}

static const char *gid_to_name(gid_t gid, char *buf, size_t size)
{
    const struct group *gr = getgrgid(gid);
    if (gr) return gr->gr_name;
    snprintf(buf, size, "%u", (unsigned)gid);
    return buf;
}

/* Prints a JSON string literal, escaping ", \, and control characters.
   Unix paths/names may contain almost any byte, so this can't be skipped. */
static void json_print_string(const char *s)
{
    putchar('"');
    for (; *s; s++)
    {
        unsigned char c = (unsigned char)*s;
        switch (c)
        {
        case '"':  fputs("\\\"", stdout); break;
        case '\\': fputs("\\\\", stdout); break;
        case '\n': fputs("\\n", stdout); break;
        case '\r': fputs("\\r", stdout); break;
        case '\t': fputs("\\t", stdout); break;
        default:
            if (c < 0x20)
                printf("\\u%04x", c);
            else
                putchar((int)c);
        }
    }
    putchar('"');
}

static void json_print_string_or_null(const char *s)
{
    if (s) json_print_string(s);
    else   fputs("null", stdout);
}

static const PathComponent *find_blocked_component(const AccessResult *result)
{
    if (!result->access_path || !result->blocked_path)
        return NULL;
    for (size_t i = 0; i < result->access_path->count; i++)
        if (strcmp(result->access_path->components[i].path, result->blocked_path) == 0)
            return &result->access_path->components[i];
    return NULL;
}

/* Mirrors output.c's print_reason() messages, but builds a string instead
   of printing: each renderer owns its own copy of the wording it needs. */
static void build_explanation(const AccessResult *result, AccessOperation op,
                              char *buf, size_t size)
{
    const PathComponent *bc = find_blocked_component(result);
    char gbuf[32];
    const char *grp = bc ? gid_to_name(bc->st.st_gid, gbuf, sizeof(gbuf)) : NULL;
    const char *o = op_name(op);

    switch (result->reason)
    {
    case REASON_GROUP_MISSING:
        snprintf(buf, size, "not in group \"%s\" (which would allow %s)", grp ? grp : "?", o);
        break;
    case REASON_GROUP_DENIED:
        snprintf(buf, size, "in group \"%s\" but the group has no %s permission", grp ? grp : "?", o);
        break;
    case REASON_OWNER_DENIED:
        snprintf(buf, size, "you own this file but lack %s permission", o);
        break;
    case REASON_ACL_DENIED:
        snprintf(buf, size, "ACL entry found for you but it does not grant %s permission", o);
        break;
    case REASON_OTHER_DENIED:
        snprintf(buf, size, "no %s permission: not the owner and not in the file's group", o);
        break;
    case REASON_NOT_TRAVERSABLE:
        snprintf(buf, size, "cannot enter this directory");
        break;
    case REASON_NOT_FOUND:
        snprintf(buf, size, "no such file or directory");
        break;
    case REASON_BROKEN_SYMLINK:
        snprintf(buf, size, "this is a symlink pointing to a target that does not exist");
        break;
    case REASON_SYMLINK_LOOP:
        snprintf(buf, size, "too many levels of symbolic links (possible loop)");
        break;
    case REASON_NONE:
        snprintf(buf, size, "access allowed");
        break;
    default:
        snprintf(buf, size, "unknown");
    }
}

static void print_trace_component(const PathComponent *comp, bool checked_full_op,
                                  bool is_blocked, AccessOperation op, bool *first)
{
    if (!*first)
        fputs(",\n", stdout);
    *first = false;

    printf("    {\n");
    printf("      \"path\": ");
    json_print_string(comp->path);
    printf(",\n");

    bool stat_failed = (comp->denial_reason == REASON_NOT_FOUND
                     || comp->denial_reason == REASON_NOT_TRAVERSABLE
                     || comp->denial_reason == REASON_BROKEN_SYMLINK
                     || comp->denial_reason == REASON_SYMLINK_LOOP);
    if (stat_failed)
    {
        printf("      \"resolved\": false,\n");
        printf("      \"checked\": \"%s\",\n", checked_full_op ? op_name(op) : "enter");
        printf("      \"allowed\": false\n");
        printf("    }");
        return;
    }

    char mbuf[6], ubuf[16], gbuf[16];
    mode_octal(comp->st.st_mode, mbuf);
    const char *owner = uid_to_name(comp->st.st_uid, ubuf, sizeof(ubuf));
    const char *grp = gid_to_name(comp->st.st_gid, gbuf, sizeof(gbuf));

    printf("      \"resolved\": true,\n");
    printf("      \"type\": \"%s\",\n", file_type_name(comp->st.st_mode));
    printf("      \"mode\": \"%s\",\n", mbuf);
    printf("      \"owner\": ");
    json_print_string(owner);
    printf(",\n      \"group\": ");
    json_print_string(grp);
    printf(",\n      \"symlink_target\": ");
    json_print_string_or_null(comp->symlink_target);
    printf(",\n      \"capabilities\": ");
    json_print_string_or_null(comp->file_caps);
    printf(",\n      \"selinux_context\": ");
    json_print_string_or_null(comp->selinux_context);
    printf(",\n      \"has_acl\": %s,\n", comp->acl ? "true" : "false");
    printf("      \"checked\": \"%s\",\n", checked_full_op ? op_name(op) : "enter");
    printf("      \"allowed\": %s\n", is_blocked ? "false" : "true");
    printf("    }");
}

static void print_header(const char *username, AccessOperation op, const char *path)
{
    printf("{\n");
    printf("  \"schema_version\": 1,\n");
    printf("  \"user\": ");
    json_print_string(username);
    printf(",\n  \"operation\": \"%s\",\n", op_name(op));
    printf("  \"path\": ");
    json_print_string(path);
    printf(",\n");
}

void render_result_json(const AccessResult *result, const char *username,
                        AccessOperation op, const char *requested_path)
{
    const char *target = requested_path;
    if (result->access_path && result->access_path->count > 0)
        target = result->access_path->components[result->access_path->count - 1].path;

    char explanation[256];
    build_explanation(result, op, explanation, sizeof(explanation));

    print_header(username, op, target);
    printf("  \"allowed\": %s,\n", result->allowed ? "true" : "false");
    printf("  \"reason\": \"%s\",\n", reason_code(result->reason));
    printf("  \"explanation\": ");
    json_print_string(explanation);
    printf(",\n  \"blocked_at\": ");
    json_print_string_or_null(result->blocked_path);
    printf(",\n  \"trace\": [\n");

    if (result->access_path)
    {
        size_t count = result->access_path->count;
        size_t limit = count;
        if (!result->allowed && result->blocked_path)
        {
            for (size_t i = 0; i < count; i++)
                if (strcmp(result->access_path->components[i].path, result->blocked_path) == 0)
                {
                    limit = i + 1;
                    break;
                }
        }

        bool first = true;
        for (size_t i = 0; i < limit; i++)
        {
            bool checked_full_op = (i == count - 1);
            bool is_blocked = (i == limit - 1) && !result->allowed;
            print_trace_component(&result->access_path->components[i], checked_full_op,
                                  is_blocked, op, &first);
        }
        if (!first)
            putchar('\n');
    }

    printf("  ]\n");
    printf("}\n");
}

void render_user_not_found_json(const char *username, AccessOperation op,
                                const char *requested_path)
{
    char explanation[160];
    snprintf(explanation, sizeof(explanation), "no such user: %s", username);

    print_header(username, op, requested_path);
    printf("  \"allowed\": false,\n");
    printf("  \"reason\": \"user_not_found\",\n");
    printf("  \"explanation\": ");
    json_print_string(explanation);
    printf(",\n  \"blocked_at\": null,\n");
    printf("  \"trace\": []\n");
    printf("}\n");
}
