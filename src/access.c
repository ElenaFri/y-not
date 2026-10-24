#include "access.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static AccessResult deny_at(AccessPath *ap, PathComponent *component,
                            AccessReason reason, bool traversal)
{
    char *blocked = strdup(component->path);
    if (!blocked)
    {
        path_free(ap);
        return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
    }
    component->denial_reason = reason;
    return (AccessResult){.allowed = false, .blocked_path = blocked,
                          .reason = reason, .blocked_on_traversal = traversal,
                          .access_path = ap};
}

static bool is_dot_entry(const char *path)
{
    if (!path)
        return false;
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
        len--;
    size_t start = len;
    while (start > 0 && path[start - 1] != '/')
        start--;
    size_t name_len = len - start;
    return (name_len == 1 && path[start] == '.') ||
           (name_len == 2 && path[start] == '.' && path[start + 1] == '.');
}

static AccessResult check_delete(const User *user, AccessPath *ap)
{
    if (!ap || ap->count == 0)
        return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
    if (ap->count == 1)
        return deny_at(ap, &ap->components[0], REASON_DELETE_ROOT, false);
    if (is_dot_entry(ap->components[ap->count - 1].path))
        return deny_at(ap, &ap->components[ap->count - 1],
                       REASON_DELETE_SPECIAL, false);

    size_t parent_index = ap->count - 2;
    PathComponent *parent = &ap->components[parent_index];
    PathComponent *target = &ap->components[ap->count - 1];

    for (size_t i = 0; i <= parent_index; i++)
    {
        PathComponent *component = &ap->components[i];
        if (component->denial_reason != REASON_NONE)
            return deny_at(ap, component, component->denial_reason, false);

        PermissionResult search = evaluate_permissions(user, &component->st,
                                                       ACCESS_EXECUTE, component->acl);
        component->can_execute = search.allowed;
        if (!search.allowed)
        {
            component->checked_permission = search;
            component->checked_permission_known = true;
            return deny_at(ap, component, search.reason, true);
        }
        if (i == parent_index)
        {
            PermissionResult write = evaluate_permissions(user, &component->st,
                                                          ACCESS_WRITE, component->acl);
            component->can_write = write.allowed;
            if (!write.allowed)
            {
                component->checked_permission = write;
                component->checked_permission_known = true;
                return deny_at(ap, component, write.reason, false);
            }
            AccessReason mount = mount_restriction_reason(
                component->mount_flags_known, component->mount_read_only,
                component->mount_noexec, &component->st, ACCESS_WRITE);
            if (mount != REASON_NONE)
            {
                component->checked_permission = (PermissionResult){
                    .allowed = false, .reason = mount, .source = PERMISSION_SOURCE_MOUNT};
                component->checked_permission_known = true;
                return deny_at(ap, component, mount, false);
            }
            component->checked_permission = write;
            component->checked_permission_known = true;
        }
    }

    if (!target->link_st_known)
        return deny_at(ap, target, REASON_NOT_FOUND, false);

    /* Inode attributes override write+ownership: an immutable or append-only
       parent directory refuses entry removal, and an immutable or append-only
       target cannot be unlinked, even by its owner or root. */
    AccessReason parent_attr = attribute_restriction_reason(
        parent->attr_flags_known, parent->attr_immutable,
        parent->attr_append_only, ACCESS_DELETE);
    if (parent_attr != REASON_NONE)
    {
        parent->checked_permission = (PermissionResult){
            .allowed = false, .reason = parent_attr, .source = PERMISSION_SOURCE_FS_ATTR};
        parent->checked_permission_known = true;
        return deny_at(ap, parent, parent_attr, false);
    }
    AccessReason target_attr = attribute_restriction_reason(
        target->attr_flags_known, target->attr_immutable,
        target->attr_append_only, ACCESS_DELETE);
    if (target_attr != REASON_NONE)
    {
        target->checked_permission = (PermissionResult){
            .allowed = false, .reason = target_attr, .source = PERMISSION_SOURCE_FS_ATTR};
        target->checked_permission_known = true;
        return deny_at(ap, target, target_attr, false);
    }

    if ((parent->st.st_mode & S_ISVTX) && user->uid != 0 &&
        user->uid != parent->st.st_uid && user->uid != target->link_st.st_uid)
        return deny_at(ap, target, REASON_STICKY_BIT, false);

    return (AccessResult){.allowed = true, .reason = REASON_NONE, .access_path = ap};
}

AccessResult check_access(const User *user,
                          const char *path,
                          AccessOperation operation)
{
    AccessPath *ap = path_resolve(path);
    if (!ap)
        return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
    if (operation == ACCESS_DELETE)
        return check_delete(user, ap);

    for (size_t i = 0; i < ap->count; i++)
    {
        PathComponent *comp = &ap->components[i];

        if (comp->denial_reason != REASON_NONE)
        {
            char *bp = strdup(comp->path);
            if (!bp)
            {
                path_free(ap);
                return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
            }
            return (AccessResult){.allowed = false,
                                  .blocked_path = bp,
                                  .reason = comp->denial_reason,
                                  .access_path = ap};
        }

        /* Evaluate all three operations: renderer needs the full picture */
        PermissionResult pr[3];
        pr[ACCESS_READ] = evaluate_permissions(user, &comp->st, ACCESS_READ, comp->acl);
        pr[ACCESS_WRITE] = evaluate_permissions(user, &comp->st, ACCESS_WRITE, comp->acl);
        pr[ACCESS_EXECUTE] = evaluate_permissions(user, &comp->st, ACCESS_EXECUTE, comp->acl);

        comp->can_read = pr[ACCESS_READ].allowed;
        comp->can_write = pr[ACCESS_WRITE].allowed;
        comp->can_execute = pr[ACCESS_EXECUTE].allowed;

        /* Intermediate directories need traversal. Creating an entry in a
           target directory requires both search (x) and write (w); checking
           search first gives a useful, path-oriented explanation. */
        bool is_last = (i == ap->count - 1);
        bool blocked_on_traversal = false;
        PermissionResult check;
        if (!is_last)
            check = pr[ACCESS_EXECUTE];
        else if (operation == ACCESS_WRITE && S_ISDIR(comp->st.st_mode))
        {
            check = pr[ACCESS_EXECUTE];
            if (!check.allowed)
                blocked_on_traversal = true;
            else
                check = pr[ACCESS_WRITE];
        }
        else
            check = pr[operation];

        if (check.allowed && is_last)
        {
            AccessReason mount_reason = mount_restriction_reason(
                comp->mount_flags_known, comp->mount_read_only,
                comp->mount_noexec, &comp->st, operation);
            if (mount_reason != REASON_NONE)
                check = (PermissionResult){.allowed = false, .reason = mount_reason,
                                           .source = PERMISSION_SOURCE_MOUNT};
            else
            {
                AccessReason attr_reason = attribute_restriction_reason(
                    comp->attr_flags_known, comp->attr_immutable,
                    comp->attr_append_only, operation);
                if (attr_reason != REASON_NONE)
                    check = (PermissionResult){.allowed = false, .reason = attr_reason,
                                               .source = PERMISSION_SOURCE_FS_ATTR};
            }
        }

        comp->checked_permission = check;
        comp->checked_permission_known = true;

        if (!check.allowed)
        {
            comp->denial_reason = check.reason;
            char *bp = strdup(comp->path);
            if (!bp)
            {
                path_free(ap);
                return (AccessResult){.allowed = false, .reason = REASON_NOT_FOUND};
            }
            return (AccessResult){.allowed = false,
                                  .blocked_path = bp,
                                  .reason = check.reason,
                                  .blocked_on_traversal = blocked_on_traversal,
                                  .access_path = ap};
        }
    }

    return (AccessResult){.allowed = true, .reason = REASON_NONE, .access_path = ap};
}

void access_result_free(AccessResult *result)
{
    if (!result)
        return;
    free(result->blocked_path);
    path_free(result->access_path);
}
