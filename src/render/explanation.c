#include "render/explanation.h"

#include <grp.h>
#include <stdio.h>
#include <string.h>

const char *access_operation_name(AccessOperation op)
{
    switch (op)
    {
    case ACCESS_READ:
        return "read";
    case ACCESS_WRITE:
        return "write";
    case ACCESS_EXECUTE:
        return "execute";
    case ACCESS_DELETE:
        return "delete";
    default:
        return "access";
    }
}

const PathComponent *access_blocked_component(const AccessResult *result)
{
    if (!result->access_path || !result->blocked_path)
        return NULL;
    for (size_t i = 0; i < result->access_path->count; i++)
    {
        const PathComponent *component = &result->access_path->components[i];
        if (component->path && strcmp(component->path, result->blocked_path) == 0)
            return component;
    }
    return NULL;
}

static const char *gid_to_name(gid_t gid, char *buffer, size_t buffer_size)
{
    struct group grp;
    struct group *found = NULL;
    char storage[1024];
    if (getgrgid_r(gid, &grp, storage, sizeof storage, &found) == 0 && found)
        snprintf(buffer, buffer_size, "%s", found->gr_name);
    else
        snprintf(buffer, buffer_size, "%u", (unsigned)gid);
    return buffer;
}

/* Render the candidate groups as a comma-separated list of quoted names,
   e.g. "staff", "backup". Returns how many groups the denial reported, so
   the caller can pick singular vs plural phrasing even if the text was
   truncated to fit the buffer. */
static unsigned format_candidate_groups(const PermissionResult *perm,
                                        char *out, size_t out_size)
{
    out[0] = '\0';
    size_t len = 0;
    unsigned n = perm->candidate_group_count;
    if (n > Y_NOT_MAX_CANDIDATE_GROUPS)
        n = Y_NOT_MAX_CANDIDATE_GROUPS;
    for (unsigned i = 0; i < n; i++)
    {
        char name_buffer[32];
        const char *name = gid_to_name(perm->candidate_group_gids[i],
                                       name_buffer, sizeof(name_buffer));
        int written = snprintf(out + len, out_size - len, "%s\"%s\"",
                               i == 0 ? "" : ", ", name);
        if (written < 0 || (size_t)written >= out_size - len)
            break;
        len += (size_t)written;
    }
    return perm->candidate_group_count;
}

/* The permission word used in a denial sentence: which right was actually
   missing on the blocked component. For a delete the obstacle is either
   traversing a parent or writing the target directory; otherwise it is the
   requested operation on the final component, or traversal of a parent. */
static const char *explanation_operation_word(const AccessResult *result,
                                              AccessOperation op,
                                              bool blocked_is_last)
{
    if (op == ACCESS_DELETE)
        return result->blocked_on_traversal ? "traverse" : "write";
    if (blocked_is_last && !result->blocked_on_traversal)
        return access_operation_name(op);
    return "traverse";
}

/* The rwx bit being tested for an ACL denial: a traversal needs search (x),
   otherwise the bit matching the requested operation. */
static unsigned acl_tested_bit(AccessOperation op, bool traversal)
{
    if (traversal)
        return 1u;
    if (op == ACCESS_READ)
        return 4u;
    if (op == ACCESS_WRITE || op == ACCESS_DELETE)
        return 2u;
    return 1u;
}

/* Resolve the group wording for the group-related denials: either a
   comma-separated candidate list (return value > 0, text in `group_list`) or a
   single group name (`*group_name_out`). Both are left empty when the blocked
   component reports an unnamed ACL group. Returns the candidate count so the
   caller can choose singular vs plural wording. */
static unsigned resolve_group_phrasing(const AccessResult *result,
                                       const PathComponent *blocked,
                                       char *name_buf, size_t name_size,
                                       const char **group_name_out,
                                       char *group_list, size_t list_size)
{
    *group_name_out = NULL;
    group_list[0] = '\0';
    if (!blocked)
        return 0;

    const PermissionResult *perm = &blocked->checked_permission;
    bool group_missing = result->reason == REASON_GROUP_MISSING &&
                         blocked->checked_permission_known;

    bool unknown_acl_group = group_missing &&
                             perm->source == PERMISSION_SOURCE_ACL_OTHER &&
                             !perm->missing_group_known;
    if (unknown_acl_group)
        return 0;

    if (group_missing && perm->candidate_group_count > 0)
        return format_candidate_groups(perm, group_list, list_size);

    gid_t group_gid = blocked->st.st_gid;
    if (group_missing && perm->missing_group_known)
        group_gid = perm->missing_group_gid;
    *group_name_out = gid_to_name(group_gid, name_buf, name_size);
    return 0;
}

/* Everything the denial wording needs that the caller already computed. */
typedef struct
{
    const char *object;       /* "file" or "directory" */
    const char *group_object; /* "file's group" or "directory's group" */
    const char *operation;    /* the missing permission word */
    const char *group_name;   /* single group name, or NULL */
    const char *group_list;   /* candidate-group list text */
    unsigned listed_groups;   /* number of candidate groups reported */
    bool blocked_is_last;     /* the blocked component is the target itself */
} ExplanationContext;

static void render_acl_denied(const AccessResult *result, AccessOperation op,
                              const PathComponent *blocked,
                              const ExplanationContext *ctx, char *buffer,
                              size_t buffer_size)
{
    bool traversal = !ctx->blocked_is_last || result->blocked_on_traversal;
    unsigned bit = acl_tested_bit(op, traversal);
    bool mask_blocks =
        blocked && blocked->checked_permission_known &&
        blocked->checked_permission.mask_applied &&
        (blocked->checked_permission.entry_permissions & bit) &&
        !(blocked->checked_permission.effective_permissions & bit);
    if (mask_blocks)
        snprintf(buffer, buffer_size,
                 "an ACL entry grants you %s, but the ACL mask removes it",
                 ctx->operation);
    else
        snprintf(buffer, buffer_size,
                 "an ACL entry applies to you but does not grant %s permission",
                 ctx->operation);
}

static void render_reason_text(const AccessResult *result, AccessOperation op,
                               const PathComponent *blocked,
                               const ExplanationContext *ctx, char *buffer,
                               size_t buffer_size)
{
    const char *name = ctx->group_name ? ctx->group_name : "?";
    switch (result->reason)
    {
    case REASON_NONE:
        snprintf(buffer, buffer_size, "access allowed");
        break;
    case REASON_GROUP_MISSING:
        if (ctx->listed_groups > 1)
            snprintf(buffer, buffer_size,
                     "not in any of the groups that would allow %s: %s",
                     ctx->operation, ctx->group_list);
        else if (ctx->listed_groups == 1)
            snprintf(buffer, buffer_size,
                     "not in group %s (which would allow %s)", ctx->group_list,
                     ctx->operation);
        else
            snprintf(buffer, buffer_size,
                     "not in group \"%s\" (which would allow %s)", name,
                     ctx->operation);
        break;
    case REASON_GROUP_DENIED:
        snprintf(buffer, buffer_size,
                 "in group \"%s\" but the group has no %s permission", name,
                 ctx->operation);
        break;
    case REASON_OWNER_DENIED:
        snprintf(buffer, buffer_size, "you own this %s but lack %s permission",
                 ctx->object, ctx->operation);
        break;
    case REASON_ACL_DENIED:
        render_acl_denied(result, op, blocked, ctx, buffer, buffer_size);
        break;
    case REASON_OTHER_DENIED:
        if (op == ACCESS_EXECUTE && blocked && S_ISREG(blocked->st.st_mode))
            snprintf(buffer, buffer_size,
                     "file is not marked executable for this user");
        else
            snprintf(buffer, buffer_size,
                     "no %s permission: not the owner and not in the %s",
                     ctx->operation, ctx->group_object);
        break;
    case REASON_NOT_TRAVERSABLE:
        snprintf(buffer, buffer_size,
                 "this path could not be inspected: y-not was denied access "
                 "while resolving it; re-run it as root for a full verdict");
        break;
    case REASON_NOT_FOUND:
        snprintf(buffer, buffer_size, "no such file or directory");
        break;
    case REASON_BROKEN_SYMLINK:
        snprintf(buffer, buffer_size,
                 "this is a symlink pointing to a target that does not exist");
        break;
    case REASON_SYMLINK_LOOP:
        snprintf(buffer, buffer_size,
                 "too many levels of symbolic links, likely a loop");
        break;
    case REASON_MOUNT_READ_ONLY:
        snprintf(buffer, buffer_size, "filesystem is mounted read-only");
        break;
    case REASON_MOUNT_NOEXEC:
        snprintf(buffer, buffer_size, "filesystem is mounted with noexec");
        break;
    case REASON_STICKY_BIT:
        snprintf(buffer, buffer_size,
                 "the parent directory has the sticky bit; you own neither the "
                 "entry nor the directory");
        break;
    case REASON_DELETE_ROOT:
        snprintf(buffer, buffer_size, "the filesystem root cannot be deleted");
        break;
    case REASON_DELETE_SPECIAL:
        snprintf(buffer, buffer_size,
                 "the special . and .. directory entries cannot be deleted");
        break;
    case REASON_IMMUTABLE:
        snprintf(buffer, buffer_size,
                 "this %s has the immutable attribute set; it cannot be changed "
                 "or removed, not even by its owner or root",
                 ctx->object);
        break;
    case REASON_APPEND_ONLY:
        if (blocked && S_ISDIR(blocked->st.st_mode))
            snprintf(buffer, buffer_size,
                     "this directory has the append-only attribute set; entries "
                     "may be added but not removed, not even by its owner or "
                     "root");
        else
            snprintf(buffer, buffer_size,
                     "this file has the append-only attribute set; it may be "
                     "appended to but not removed, not even by its owner or "
                     "root");
        break;
    default:
        snprintf(buffer, buffer_size, "unknown");
    }
}

void format_access_explanation(const AccessResult *result, AccessOperation op,
                               char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
        return;

    const PathComponent *blocked = access_blocked_component(result);

    bool blocked_is_last = true;
    if (result->access_path && result->blocked_path &&
        result->access_path->count > 0)
    {
        const char *last_path =
            result->access_path->components[result->access_path->count - 1].path;
        blocked_is_last =
            last_path && strcmp(last_path, result->blocked_path) == 0;
    }

    char group_buffer[32];
    char group_list[256];
    const char *group_name = NULL;
    unsigned listed_groups =
        resolve_group_phrasing(result, blocked, group_buffer,
                               sizeof group_buffer, &group_name, group_list,
                               sizeof group_list);

    bool is_dir = blocked && S_ISDIR(blocked->st.st_mode);
    ExplanationContext ctx = {
        .object = is_dir ? "directory" : "file",
        .group_object = is_dir ? "directory's group" : "file's group",
        .operation = explanation_operation_word(result, op, blocked_is_last),
        .group_name = group_name,
        .group_list = group_list,
        .listed_groups = listed_groups,
        .blocked_is_last = blocked_is_last,
    };

    render_reason_text(result, op, blocked, &ctx, buffer, buffer_size);
}
