#include "render/output.h"
#include "render/explanation.h"
#include "render/remediation.h"

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

/* The bit-level justification of a denial: which permission rule decided it
   and the rwx bits it yielded, e.g. "named ACL user entry: rw- & ACL mask
   r-- = r--" or "Unix other bits: ---". Shown as the "proof:" line. */
static void format_proof(const PermissionResult *perm, char *buf, size_t size)
{
    static const char *sources[] = {"none", "Unix owner bits", "Unix group bits",
        "Unix other bits", "ACL owner entry", "named ACL user entry",
        "matching ACL group entries", "ACL other entry", "root DAC override",
        "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "mount restriction",
        "filesystem attribute"};
    const char *src = perm->source <= PERMISSION_SOURCE_FS_ATTR
                          ? sources[perm->source] : "unknown";
    unsigned bits = perm->entry_permissions;
    char entry[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
    if (perm->mask_applied)
    {
        bits = perm->mask_permissions;
        char mask[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
        bits = perm->effective_permissions;
        char effective[4] = {bits & 4u ? 'r' : '-', bits & 2u ? 'w' : '-', bits & 1u ? 'x' : '-', '\0'};
        snprintf(buf, size, "%s: %s & ACL mask %s = %s", src, entry, mask, effective);
    }
    else
        snprintf(buf, size, "%s: %s", src, entry);
}

/* The access word shown in the tree for component `i`: for a delete, the parent
   of the target shows "delete entry" and the rest "enter"; otherwise the final
   component shows the requested operation and the parents show "enter". */
static const char *tree_checked_word(const AccessResult *result,
                                     AccessOperation op, size_t i, size_t count,
                                     bool is_last)
{
    if (op == ACCESS_DELETE)
        return i == count - 2 ? "delete entry" : "enter";
    if (is_last && !result->blocked_on_traversal)
        return access_operation_name(op);
    return "enter";
}

/* The trailing "(caps: …) (selinux: …) (mount: …) (attr: …)" annotations for a
   tree component. Each is printed only when the fact is known and non-default,
   so a plain file shows none. Kept out of render_tree to hold its complexity
   down; the exact spacing and wording is asserted by test_output.c. */
static void render_component_annotations(const PathComponent *comp)
{
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
    if (comp->attr_flags_known && (comp->attr_immutable || comp->attr_append_only))
    {
        fputs("  (attr:", stdout);
        if (comp->attr_immutable) fputs(" immutable", stdout);
        if (comp->attr_append_only) fputs(" append-only", stdout);
        putchar(')');
    }
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
            else if (comp->denial_reason == REASON_NOT_TRAVERSABLE)
                msg = "(access denied)";
            printf("%s\n", msg);
            continue;
        }

        char mstr[10], ubuf[16], gbuf[16];
        mode_str(comp->st.st_mode, mstr);
        const char *owner = uid_to_name(comp->st.st_uid, ubuf, sizeof(ubuf));
        const char *grp = gid_to_name(comp->st.st_gid, gbuf, sizeof(gbuf));

        const char *checked =
            tree_checked_word(result, op, i, ap->count, is_last);
        printf("%c%s  %s:%s   %-7s  %s",
               file_type_char(comp->st.st_mode), mstr,
               owner, grp, checked, is_block ? "BLOCKED" : "ok");
        render_component_annotations(comp);
        putchar('\n');
    }
}

/* The kernel cross-check line, aligned on the same label column as the denial
   block. CONFIRMED reassures (the kernel agrees), MISMATCH is the useful signal
   (the kernel disagrees - the DIVERGENT detail says which way and why), and an
   unverified result is shown with the honest reason it could not be checked. */
static void render_verification(const Verification *v, bool allowed)
{
    if (!v)
        return;

    char line[640];
    const char *label;
    switch (v->status)
    {
    case VERIFICATION_CONFIRMED:
        label = "verified:";
        snprintf(line, sizeof(line), "the kernel agrees this access is %s",
                 allowed ? "allowed" : "denied");
        break;
    case VERIFICATION_DIVERGENT:
        label = "MISMATCH:";
        snprintf(line, sizeof(line), "%s", v->detail ? v->detail : "");
        break;
    case VERIFICATION_NOT_PROBED:
    default:
        if (!v->detail)
            return;
        label = "unverified:";
        snprintf(line, sizeof(line), "%s", v->detail);
        break;
    }
    printf("  %-12s%s\n", label, line);
}

/* The "allowed for:" line listing which of the compared accounts are allowed.
   A human label under the verdict; JSON carries the allowed_for array. */
static void render_compared_line(const ComparedUsers *compared)
{
    if (!compared || !compared->requested)
        return;
    fputs("  allowed for: ", stdout);
    if (compared->allowed_count == 0)
    {
        fputs("none\n", stdout);
        return;
    }
    for (size_t i = 0; i < compared->allowed_count; i++)
    {
        if (i)
            fputs(", ", stdout);
        fputs(compared->allowed[i], stdout);
    }
    putchar('\n');
}

/* The "proof:" line: the bit-level justification for a denial, or the inode
   attribute / sticky-bit facts when no permission bits decided it. */
static void render_proof_line(const AccessResult *result)
{
    if (result->reason == REASON_IMMUTABLE)
    {
        printf("  %-12sthe immutable attribute is set on this entry\n",
               "proof:");
        return;
    }
    if (result->reason == REASON_APPEND_ONLY)
    {
        printf("  %-12sthe append-only attribute is set on this entry\n",
               "proof:");
        return;
    }

    const PathComponent *blocked = access_blocked_component(result);
    if (blocked && blocked->checked_permission_known)
    {
        char proof[128];
        format_proof(&blocked->checked_permission, proof, sizeof proof);
        printf("  %-12s%s\n", "proof:", proof);
        return;
    }

    if (result->reason == REASON_STICKY_BIT && result->access_path &&
        result->access_path->count >= 2)
    {
        const PathComponent *entry =
            &result->access_path->components[result->access_path->count - 1];
        const PathComponent *parent =
            &result->access_path->components[result->access_path->count - 2];
        char entry_owner_buf[16];
        char dir_owner_buf[16];
        const char *entry_owner = uid_to_name(
            entry->link_st.st_uid, entry_owner_buf, sizeof entry_owner_buf);
        const char *dir_owner = uid_to_name(parent->st.st_uid, dir_owner_buf,
                                            sizeof dir_owner_buf);
        printf("  %-12ssticky bit set; entry owner %s, directory owner %s\n",
               "proof:", entry_owner, dir_owner);
    }
}

/* The denial detail block: blocked-at, cause, proof and the to-allow remedy. */
static void render_denial_details(const AccessResult *result, const User *user,
                                  AccessOperation op)
{
    if (result->blocked_path)
        printf("\n  %-12s%s\n", "blocked at:", result->blocked_path);

    char explanation[512];
    format_access_explanation(result, op, explanation, sizeof explanation);
    printf("  %-12s%s\n", "cause:", explanation);

    render_proof_line(result);

    char remedy[512];
    if (format_remediation(result, op, user->name, remedy, sizeof remedy))
        printf("  %-12s%s\n", "to allow:", remedy);
}

void render_result_text(const AccessResult *result, const User *user,
                        AccessOperation op, const ComparedUsers *compared,
                        const Verification *verification)
{
    const char *target = "?";
    if (result->access_path && result->access_path->count > 0)
        target = result->access_path->components[result->access_path->count - 1].path;

    SelinuxStatus se = selinux_status();
    ApparmorStatus aa = apparmor_status();
    MacWarning mac = mac_warning_evaluate(result->allowed, se, aa);

    putchar('\n');
    printf("%s %s %s %s\n", user->name, result->allowed ? "can" : "cannot",
           access_operation_name(op), target);

    /* The "allowed for:" line sits right under the verdict, at the same left
       margin. It is a human label, not a stable field - the --json output
       carries the machine-readable "allowed_for" array instead. */
    render_compared_line(compared);

    if (!result->allowed)
        render_denial_details(result, user, op);

    /* Kernel cross-check: y-not's verdict is the modeled one, but when it could
       ask the kernel too (via access(2) under the target identity), it reports
       whether the kernel agrees. A MISMATCH is the useful case - most often a
       security module denying access the DAC/ACL model would grant. */
    render_verification(verification, result->allowed);

    /* MAC honesty: when the DAC/ACL verdict is "allowed" but a mandatory
       access control module is active, say so right under the verdict. The
       kernel may still deny a confined process, and y-not does not model that,
       so an admin must never read an "allowed" here as "the access is free". */
    if (mac.may_override_verdict)
    {
        char warn[256];
        mac_warning_message(mac, warn, sizeof(warn));
        printf("\n  %-12s%s\n", "warning:", warn);
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
