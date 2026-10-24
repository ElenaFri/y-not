#include "render/json_output.h"
#include "render/explanation.h"
#include "render/remediation.h"

#include "context/apparmor_info.h"
#include "context/mac_warning.h"
#include "context/selinux_info.h"

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
    case REASON_STICKY_BIT:      return "sticky_bit";
    case REASON_DELETE_ROOT:    return "delete_root";
    case REASON_DELETE_SPECIAL: return "delete_special";
    case REASON_IMMUTABLE:      return "immutable";
    case REASON_APPEND_ONLY:    return "append_only";
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
        "cap_dac_override", "cap_dac_read_search", "mount", "fs_attr"};
    return source <= PERMISSION_SOURCE_FS_ATTR ? names[source] : "unknown";
}

static void permission_text(unsigned bits, char out[4])
{
    out[0] = bits & 4u ? 'r' : '-';
    out[1] = bits & 2u ? 'w' : '-';
    out[2] = bits & 1u ? 'x' : '-';
    out[3] = '\0';
}

/* A component whose stat(2) failed: emit it as unresolved with its reason. */
static void print_unresolved_component(const PathComponent *comp,
                                       bool checked_full_op, bool is_target,
                                       AccessOperation op)
{
    printf("      \"resolved\": false,\n");
    if (op == ACCESS_DELETE && is_target && comp->link_st_known)
    {
        char entry_owner_buf[16];
        const char *entry_owner = uid_to_name(
            comp->link_st.st_uid, entry_owner_buf, sizeof entry_owner_buf);
        printf("      \"entry_owner\": ");
        json_print_string(entry_owner);
        printf(",\n");
    }
    printf("      \"checked\": \"%s\",\n",
           checked_full_op ? access_operation_name(op) : "enter");
    printf("      \"allowed\": false\n");
    printf("    }");
}

/* The additive "decision" object: which permission rule decided this component,
   the rwx bits it produced, and any candidate groups. */
static void print_decision(const PermissionResult *perm)
{
    char entry[4], effective[4], mask[4];
    permission_text(perm->entry_permissions, entry);
    permission_text(perm->effective_permissions, effective);
    permission_text(perm->mask_permissions, mask);
    printf(",\n      \"decision\": {\"source\": \"%s\", \"entry_permissions\": \"%s\", \"effective_permissions\": \"%s\", \"mask_applied\": %s, \"mask_permissions\": \"%s\", \"missing_group_gid\": ",
           permission_source_name(perm->source), entry, effective,
           perm->mask_applied ? "true" : "false", mask);
    if (perm->missing_group_known)
        printf("%u", (unsigned)perm->missing_group_gid);
    else
        fputs("null", stdout);
    fputs(", \"candidate_groups\": [", stdout);
    for (unsigned g = 0; g < perm->candidate_group_count; g++)
    {
        if (g)
            putchar(',');
        gid_t cg = perm->candidate_group_gids[g];
        char cgbuf[16];
        const char *cgname = gid_to_name(cg, cgbuf, sizeof cgbuf);
        printf("{\"gid\": %u, \"name\": ", (unsigned)cg);
        json_print_string(cgname);
        putchar('}');
    }
    putchar(']');
    putchar('}');
}

static void print_trace_component(const PathComponent *comp, bool checked_full_op,
                                  bool is_blocked, bool is_target, AccessOperation op,
                                  bool *first)
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
        print_unresolved_component(comp, checked_full_op, is_target, op);
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
    if (op == ACCESS_DELETE && is_target && comp->link_st_known)
    {
        char entry_owner_buf[16];
        const char *entry_owner = uid_to_name(comp->link_st.st_uid, entry_owner_buf,
                                              sizeof(entry_owner_buf));
        printf(",\n      \"entry_owner\": ");
        json_print_string(entry_owner);
    }
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
        print_decision(&comp->checked_permission);
    putchar('\n');
    printf("    }");
}

/* The "mac" object documents mandatory access control honestly: y-not never
   evaluates MAC policy ("evaluated": false), so when a module is active and the
   verdict is "allowed", "may_override_verdict" is true and "warning" carries the
   human-readable caveat - the same one the text renderer prints. */
static void print_mac(bool allowed)
{
    SelinuxStatus se = selinux_status();
    ApparmorStatus aa = apparmor_status();
    MacWarning mac = mac_warning_evaluate(allowed, se, aa);

    fputs("  \"mac\": {\n", stdout);

    fputs("    \"selinux\": {\"available\": ", stdout);
    fputs(se.available ? "true" : "false", stdout);
    fputs(", \"enforcing\": ", stdout);
    if (se.available)
        fputs(se.enforcing == 1 ? "true" : "false", stdout);
    else
        fputs("null", stdout);
    fputs("},\n", stdout);

    fputs("    \"apparmor\": {\"available\": ", stdout);
    fputs(aa.available ? "true" : "false", stdout);
    fputs(", \"profiles_loaded\": ", stdout);
    if (aa.available && aa.profile_count >= 0)
        printf("%d", aa.profile_count);
    else
        fputs("null", stdout);
    fputs("},\n", stdout);

    fputs("    \"evaluated\": false,\n", stdout);
    printf("    \"may_override_verdict\": %s,\n",
           mac.may_override_verdict ? "true" : "false");

    fputs("    \"warning\": ", stdout);
    if (mac.may_override_verdict)
    {
        char warn[256];
        mac_warning_message(mac, warn, sizeof(warn));
        json_print_string(warn);
    }
    else
    {
        fputs("null", stdout);
    }
    fputs("\n  },\n", stdout);
}

/* The additive "verification" object reports the kernel cross-check: y-not's
   verdict stays the modeled one, this only says whether access(2) under the
   target identity agreed. "kernel_allowed" is null when the probe did not run
   (status "not_probed"), and "detail" carries the honest reason or the
   divergence sentence. schema_version stays 1 - the key is only ever added. */
static void print_verification(const Verification *v)
{
    const char *status;
    switch (v->status)
    {
    case VERIFICATION_CONFIRMED: status = "confirmed"; break;
    case VERIFICATION_DIVERGENT: status = "divergent"; break;
    case VERIFICATION_NOT_PROBED:
    default:                     status = "not_probed"; break;
    }

    printf("  \"verification\": {\"status\": \"%s\", \"kernel_allowed\": ", status);
    if (v->status == VERIFICATION_NOT_PROBED)
        fputs("null", stdout);
    else
        fputs(v->kernel_allowed ? "true" : "false", stdout);
    fputs(", \"detail\": ", stdout);
    json_print_string_or_null(v->detail);
    fputs("},\n", stdout);
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

/* Additive "allowed_for" array: only emitted when --compare was given, so
   consumers of the base schema never see a new required key. */
static void print_allowed_for(const ComparedUsers *compared)
{
    if (!compared || !compared->requested)
        return;
    fputs("  \"allowed_for\": [", stdout);
    for (size_t i = 0; i < compared->allowed_count; i++)
    {
        if (i)
            putchar(',');
        json_print_string(compared->allowed[i]);
    }
    fputs("],\n", stdout);
}

static void print_trace(const AccessResult *result, AccessOperation op)
{
    printf("  \"trace\": [\n");
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
            bool checked_full_op = (op == ACCESS_DELETE
                                        ? i == count - 2
                                        : i == count - 1) &&
                                   !result->blocked_on_traversal;
            bool is_blocked = (i == limit - 1) && !result->allowed;
            print_trace_component(&result->access_path->components[i], checked_full_op,
                                  is_blocked, i == count - 1, op, &first);
        }
        if (!first)
            putchar('\n');
    }
    printf("  ]\n");
}

void render_result_json(const AccessResult *result, const char *username,
                        AccessOperation op, const char *requested_path,
                        const ComparedUsers *compared,
                        const Verification *verification)
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
    char remedy[512];
    printf(",\n  \"remediation\": ");
    if (format_remediation(result, op, username, remedy, sizeof(remedy)))
        json_print_string(remedy);
    else
        fputs("null", stdout);
    printf(",\n  \"blocked_at\": ");
    json_print_string_or_null(result->blocked_path);
    printf(",\n");
    print_allowed_for(compared);
    if (verification)
        print_verification(verification);
    print_mac(result->allowed);
    print_trace(result, op);

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
    printf(",\n  \"remediation\": null,\n  \"blocked_at\": null,\n");
    print_mac(false);
    printf("  \"trace\": []\n");
    printf("}\n");
}
