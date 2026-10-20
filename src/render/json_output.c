#include "render/json_output.h"
#include "render/explanation.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

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
    case REASON_MOUNT_READ_ONLY: return "mount_read_only";
    case REASON_MOUNT_NOEXEC:    return "mount_noexec";
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

static const char *permission_source_name(PermissionSource source)
{
    static const char *names[] = {"none", "unix_owner", "unix_group", "unix_other",
        "acl_owner", "acl_user", "acl_group", "acl_other", "dac_override",
        "cap_dac_override", "cap_dac_read_search", "mount"};
    return source <= PERMISSION_SOURCE_MOUNT ? names[source] : "unknown";
}

static void permission_text(unsigned bits, char out[4])
{
    out[0] = bits & 4u ? 'r' : '-';
    out[1] = bits & 2u ? 'w' : '-';
    out[2] = bits & 1u ? 'x' : '-';
    out[3] = '\0';
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
        printf("      \"checked\": \"%s\",\n", checked_full_op ? access_operation_name(op) : "enter");
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
    printf(",\n      \"mount_flags\": {\"known\": %s, \"read_only\": %s, \"noexec\": %s, \"nosuid\": %s},\n",
           comp->mount_flags_known ? "true" : "false",
           comp->mount_read_only ? "true" : "false",
           comp->mount_noexec ? "true" : "false",
           comp->mount_nosuid ? "true" : "false");
    printf("      \"has_acl\": %s,\n", comp->acl ? "true" : "false");
    printf("      \"checked\": \"%s\",\n", checked_full_op ? access_operation_name(op) : "enter");
    printf("      \"allowed\": %s", is_blocked ? "false" : "true");
    if (comp->checked_permission_known)
    {
        char entry[4], effective[4], mask[4];
        permission_text(comp->checked_permission.entry_permissions, entry);
        permission_text(comp->checked_permission.effective_permissions, effective);
        permission_text(comp->checked_permission.mask_permissions, mask);
        printf(",\n      \"decision\": {\"source\": \"%s\", \"entry_permissions\": \"%s\", \"effective_permissions\": \"%s\", \"mask_applied\": %s, \"mask_permissions\": \"%s\", \"missing_group_gid\": ",
               permission_source_name(comp->checked_permission.source), entry, effective,
               comp->checked_permission.mask_applied ? "true" : "false", mask);
        if (comp->checked_permission.missing_group_known)
            printf("%u", (unsigned)comp->checked_permission.missing_group_gid);
        else
            fputs("null", stdout);
        fputs(", \"candidate_groups\": [", stdout);
        for (unsigned g = 0; g < comp->checked_permission.candidate_group_count; g++)
        {
            if (g)
                putchar(',');
            gid_t cg = comp->checked_permission.candidate_group_gids[g];
            char cgbuf[16];
            const char *cgname = gid_to_name(cg, cgbuf, sizeof(cgbuf));
            printf("{\"gid\": %u, \"name\": ", (unsigned)cg);
            json_print_string(cgname);
            putchar('}');
        }
        putchar(']');
        putchar('}');
    }
    putchar('\n');
    printf("    }");
}

static void print_header(const char *username, AccessOperation op, const char *path)
{
    printf("{\n");
    printf("  \"schema_version\": 1,\n");
    printf("  \"user\": ");
    json_print_string(username);
    printf(",\n  \"operation\": \"%s\",\n", access_operation_name(op));
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

    char explanation[512];
    format_access_explanation(result, op, explanation, sizeof(explanation));

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
            bool checked_full_op = (i == count - 1) &&
                                   !result->blocked_on_traversal;
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
