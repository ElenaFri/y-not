#include "render/output.h"
#include "render/explanation.h"

#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include "context/apparmor_info.h"
#include "context/mac_warning.h"
#include "context/selinux_info.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static char file_type_char(mode_t mode)
{
    if (S_ISDIR(mode))
        return 'd';
    if (S_ISLNK(mode))
        return 'l';
    if (S_ISCHR(mode))
        return 'c';
    if (S_ISBLK(mode))
        return 'b';
    if (S_ISFIFO(mode))
        return 'p';
    if (S_ISSOCK(mode))
        return 's';
    return '-';
}

static void mode_str(mode_t mode, char buf[10])
{
    static const mode_t bits[] = {
        S_IRUSR,
        S_IWUSR,
        S_IXUSR,
        S_IRGRP,
        S_IWGRP,
        S_IXGRP,
        S_IROTH,
        S_IWOTH,
        S_IXOTH,
    };
    for (int i = 0; i < 9; i++)
        buf[i] = (mode & bits[i]) ? "rwxrwxrwx"[i] : '-';
    buf[9] = '\0';
}

static const char *uid_to_name(uid_t uid, char *buf, size_t size)
{
    const struct passwd *pw = getpwuid(uid);
    if (pw)
        return pw->pw_name;
    snprintf(buf, size, "%u", (unsigned)uid);
    return buf;
}

static const char *gid_to_name(gid_t gid, char *buf, size_t size)
{
    const struct group *gr = getgrgid(gid);
    if (gr)
        return gr->gr_name;
    snprintf(buf, size, "%u", (unsigned)gid);
    return buf;
}

static const char *basename_of(const char *path)
{
    const char *p = strrchr(path, '/');
    return (p && *(p + 1)) ? p + 1 : path;
}

/* "name" or "name -> target" for symlink components. */
static void display_name(const PathComponent *comp, bool is_root, char *buf, size_t size)
{
    const char *name = is_root ? "/" : basename_of(comp->path);
    if (comp->is_symlink && comp->symlink_target)
        snprintf(buf, size, "%s -> %s", name, comp->symlink_target);
    else
        snprintf(buf, size, "%s", name);
}

static void render_tree(const AccessResult *result, AccessOperation op)
{
    const AccessPath *ap = result->access_path;
    if (!ap)
        return;

    /* First pass: max label display-width for column alignment.
       U+2514 U+2500 U+2500 space = 4 display cols but 10 UTF-8 bytes. */
    size_t col = 0;
    for (size_t i = 0; i < ap->count; i++)
    {
        char dn[PATH_MAX];
        display_name(&ap->components[i], i == 0, dn, sizeof(dn));
        size_t w = (i > 0 ? (i - 1) * 4 + 4 : 0) + strlen(dn);
        if (w > col)
            col = w;
    }
    col += 2;

    bool past_block = false;
    for (size_t i = 0; i < ap->count; i++)
    {
        const PathComponent *comp = &ap->components[i];
        bool is_last = (i == ap->count - 1);
        bool is_block = (result->allowed == false) && result->blocked_path && strcmp(comp->path, result->blocked_path) == 0;

        char dn[PATH_MAX];
        display_name(comp, i == 0, dn, sizeof(dn));

        if (i == 0)
        {
            printf("  %-*s", (int)col, "/");
        }
        else
        {
            /* Indentation is printed via printf's own width padding, not a
               fixed buffer: a deeply nested path must never risk a stack
               overflow just to render prettily. */
            size_t indent = (i - 1) * 4;
            char connector[PATH_MAX + 16];
            snprintf(connector, sizeof(connector),
                     "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 %s", dn);

            /* the tree connector is 10 UTF-8 bytes but 4 display cols;
               add 6 so the printed width still lines up visually. */
            int connector_width = (int)(col - indent) + 6;
            printf("  %*s%-*s", (int)indent, "", connector_width, connector);
        }

        if (past_block)
        {
            putchar('\n');
            continue;
        }
        if (is_block)
            past_block = true;

        /* stat(2) failed: st fields are uninitialized (zeroed by calloc) */
        bool stat_failed = (comp->denial_reason == REASON_NOT_FOUND || comp->denial_reason == REASON_NOT_TRAVERSABLE || comp->denial_reason == REASON_BROKEN_SYMLINK || comp->denial_reason == REASON_SYMLINK_LOOP);
        if (stat_failed)
        {
            const char *msg = "(not found)";
            if (comp->denial_reason == REASON_BROKEN_SYMLINK)
                msg = "(broken symlink)";
            else if (comp->denial_reason == REASON_SYMLINK_LOOP)
                msg = "(symlink loop)";
            printf("%s\n", msg);
            continue;
        }

        char mstr[10], ubuf[16], gbuf[16];
        mode_str(comp->st.st_mode, mstr);
        const char *owner = uid_to_name(comp->st.st_uid, ubuf, sizeof(ubuf));
        const char *grp = gid_to_name(comp->st.st_gid, gbuf, sizeof(gbuf));

        const char *checked = (is_last && !result->blocked_on_traversal)
                                  ? access_operation_name(op)
                                  : "enter";
        printf("%c%s  %s:%s   %-7s  %s",
               file_type_char(comp->st.st_mode), mstr,
               owner, grp, checked, is_block ? "BLOCKED" : "ok");
        if (comp->file_caps)
            printf("  (caps: %s)", comp->file_caps);
        if (comp->selinux_context)
            printf("  (selinux: %s)", comp->selinux_context);
        if (comp->mount_flags_known &&
            (comp->mount_read_only || comp->mount_noexec || comp->mount_nosuid))
        {
            fputs("  (mount:", stdout);
            if (comp->mount_read_only) fputs(" ro", stdout);
            if (comp->mount_noexec) fputs(" noexec", stdout);
            if (comp->mount_nosuid) fputs(" nosuid", stdout);
            putchar(')');
        }
        putchar('\n');
        if (is_block && comp->checked_permission_known)
        {
            static const char *sources[] = {"none", "Unix owner bits", "Unix group bits",
                "Unix other bits", "ACL owner entry", "named ACL user entry",
                "matching ACL group entries", "ACL other entry", "root DAC override",
                "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "mount restriction"};
            unsigned bits = comp->checked_permission.entry_permissions;
            char entry[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
            bits = comp->checked_permission.effective_permissions;
            char effective[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
            PermissionSource source = comp->checked_permission.source;
            printf("    decision    %s: %s", source <= PERMISSION_SOURCE_MOUNT ? sources[source] : "unknown", entry);
            if (comp->checked_permission.mask_applied)
            {
                bits = comp->checked_permission.mask_permissions;
                char mask[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
                printf(" & ACL mask %s = %s", mask, effective);
            }
            putchar('\n');
        }
    }
}

void render_result_text(const AccessResult *result, const User *user, AccessOperation op)
{
    const char *target = "?";
    if (result->access_path && result->access_path->count > 0)
        target = result->access_path->components[result->access_path->count - 1].path;

    SelinuxStatus se = selinux_status();
    ApparmorStatus aa = apparmor_status();
    MacWarning mac = mac_warning_evaluate(result->allowed, se, aa);

    putchar('\n');
    if (result->allowed)
    {
        printf("%s can %s %s\n", user->name, access_operation_name(op), target);
    }
    else
    {
        printf("%s cannot %s %s\n", user->name, access_operation_name(op), target);
        if (result->blocked_path)
            printf("\n  blocked at  %s\n", result->blocked_path);
        char explanation[512];
        format_access_explanation(result, op, explanation, sizeof(explanation));
        printf("  reason      %s\n", explanation);
    }

    /* MAC honesty: when the DAC/ACL verdict is "allowed" but a mandatory
       access control module is active, say so right under the verdict. The
       kernel may still deny a confined process, and y-not does not model that,
       so an admin must never read an "allowed" here as "the access is free". */
    if (mac.may_override_verdict)
    {
        char warn[256];
        mac_warning_message(mac, warn, sizeof(warn));
        printf("\n  warning     %s\n", warn);
    }

    putchar('\n');
    render_tree(result, op);
    putchar('\n');

    /* MAC status: only shown when something is actually active, to avoid
       cluttering the common case of a plain DAC/ACL-only system. */
    if (se.available)
        printf("SELinux: %s\n", se.enforcing == 1 ? "enforcing" : "permissive");

    if (aa.available)
    {
        if (aa.profile_count >= 0)
            printf("AppArmor: enabled (%d profiles loaded)\n", aa.profile_count);
        else
            printf("AppArmor: enabled (profile count needs elevated privilege)\n");
    }
}
