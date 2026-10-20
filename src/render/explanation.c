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
    default:
        return "access";
    }
}

static const PathComponent *find_blocked_component(const AccessResult *result)
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
    const struct group *group = getgrgid(gid);
    if (group)
        return group->gr_name;
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

void format_access_explanation(const AccessResult *result, AccessOperation op,
                               char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
        return;

    const PathComponent *blocked = find_blocked_component(result);
    bool blocked_is_last = true;
    if (result->access_path && result->blocked_path && result->access_path->count > 0)
    {
        const char *last_path = result->access_path->components[
            result->access_path->count - 1].path;
        blocked_is_last = last_path && strcmp(last_path, result->blocked_path) == 0;
    }

    char group_buffer[32];
    const char *group_name = NULL;
    char group_list[256];
    group_list[0] = '\0';
    unsigned listed_groups = 0;
    if (blocked)
    {
        bool unknown_acl_group = result->reason == REASON_GROUP_MISSING &&
                                 blocked->checked_permission_known &&
                                 blocked->checked_permission.source == PERMISSION_SOURCE_ACL_OTHER &&
                                 !blocked->checked_permission.missing_group_known;
        if (!unknown_acl_group)
        {
            const PermissionResult *perm = &blocked->checked_permission;
            if (result->reason == REASON_GROUP_MISSING &&
                blocked->checked_permission_known &&
                perm->candidate_group_count > 0)
            {
                listed_groups = format_candidate_groups(perm, group_list,
                                                        sizeof(group_list));
            }
            else
            {
                gid_t group_gid = blocked->st.st_gid;
                if (result->reason == REASON_GROUP_MISSING &&
                    blocked->checked_permission_known &&
                    perm->missing_group_known)
                    group_gid = perm->missing_group_gid;
                group_name = gid_to_name(group_gid, group_buffer, sizeof(group_buffer));
            }
        }
    }

    const char *object = blocked && S_ISDIR(blocked->st.st_mode) ? "directory" : "file";
    const char *group_object = blocked && S_ISDIR(blocked->st.st_mode)
                                   ? "directory's group"
                                   : "file's group";
    const char *operation = blocked_is_last && !result->blocked_on_traversal
                                ? access_operation_name(op)
                                : "traverse";

    switch (result->reason)
    {
    case REASON_NONE:
        snprintf(buffer, buffer_size, "access allowed");
        break;
    case REASON_GROUP_MISSING:
        if (listed_groups > 1)
            snprintf(buffer, buffer_size,
                     "not in any of the groups that would allow %s: %s",
                     operation, group_list);
        else if (listed_groups == 1)
            snprintf(buffer, buffer_size, "not in group %s (which would allow %s)",
                     group_list, operation);
        else
            snprintf(buffer, buffer_size, "not in group \"%s\" (which would allow %s)",
                     group_name ? group_name : "?", operation);
        break;
    case REASON_GROUP_DENIED:
        snprintf(buffer, buffer_size, "in group \"%s\" but the group has no %s permission",
                 group_name ? group_name : "?", operation);
        break;
    case REASON_OWNER_DENIED:
        snprintf(buffer, buffer_size, "you own this %s but lack %s permission",
                 object, operation);
        break;
    case REASON_ACL_DENIED:
        snprintf(buffer, buffer_size,
                 "ACL entry found for you but it does not grant %s permission", operation);
        break;
    case REASON_OTHER_DENIED:
        if (op == ACCESS_EXECUTE && blocked && S_ISREG(blocked->st.st_mode))
            snprintf(buffer, buffer_size,
                     "file is not marked executable for this user");
        else
            snprintf(buffer, buffer_size,
                     "no %s permission: not the owner and not in the %s",
                     operation, group_object);
        break;
    case REASON_NOT_TRAVERSABLE:
        snprintf(buffer, buffer_size, "cannot enter this directory");
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
                 "too many levels of symbolic links (possible loop)");
        break;
    case REASON_MOUNT_READ_ONLY:
        snprintf(buffer, buffer_size, "filesystem is mounted read-only");
        break;
    case REASON_MOUNT_NOEXEC:
        snprintf(buffer, buffer_size, "filesystem is mounted with noexec");
        break;
    default:
        snprintf(buffer, buffer_size, "unknown");
    }
}
