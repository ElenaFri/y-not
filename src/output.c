#include "output.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

static char file_type_char(mode_t mode)
{
    if (S_ISDIR(mode))  return 'd';
    if (S_ISLNK(mode))  return 'l';
    if (S_ISCHR(mode))  return 'c';
    if (S_ISBLK(mode))  return 'b';
    if (S_ISFIFO(mode)) return 'p';
    if (S_ISSOCK(mode)) return 's';
    return '-';
}

static void mode_str(mode_t mode, char buf[10])
{
    static const mode_t bits[] = {
        S_IRUSR, S_IWUSR, S_IXUSR,
        S_IRGRP, S_IWGRP, S_IXGRP,
        S_IROTH, S_IWOTH, S_IXOTH,
    };
    for (int i = 0; i < 9; i++)
        buf[i] = (mode & bits[i]) ? "rwxrwxrwx"[i] : '-';
    buf[9] = '\0';
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

static const char *basename_of(const char *path)
{
    const char *p = strrchr(path, '/');
    return (p && *(p + 1)) ? p + 1 : path;
}

static const char *op_name(AccessOperation op)
{
    switch (op) {
        case ACCESS_READ:    return "read";
        case ACCESS_WRITE:   return "write";
        case ACCESS_EXECUTE: return "execute";
        default:             return "access";
    }
}

static void print_reason(const AccessResult *result)
{
    const PathComponent *bc = NULL;
    if (result->access_path && result->blocked_path) {
        for (size_t i = 0; i < result->access_path->count; i++) {
            if (strcmp(result->access_path->components[i].path,
                       result->blocked_path) == 0) {
                bc = &result->access_path->components[i];
                break;
            }
        }
    }

    char gbuf[32];
    const char *grp = bc ? gid_to_name(bc->st.st_gid, gbuf, sizeof(gbuf)) : NULL;

    switch (result->reason) {
        case REASON_GROUP_MISSING:
            printf("   reason      not in group \"%s\" (which has this permission)\n",
                   grp ? grp : "?");
            break;
        case REASON_GROUP_DENIED:
            printf("   reason      in group \"%s\" but group bits deny this\n",
                   grp ? grp : "?");
            break;
        case REASON_OWNER_DENIED:
            printf("   reason      owner bits do not allow this\n");
            break;
        case REASON_OTHER_DENIED:
            printf("   reason      other bits do not allow this\n");
            break;
        case REASON_NOT_TRAVERSABLE:
            printf("   reason      directory is not traversable\n");
            break;
        case REASON_NOT_FOUND:
            printf("   reason      no such file or directory\n");
            break;
        default:
            printf("   reason      unknown\n");
    }
}

static void render_tree(const AccessResult *result, AccessOperation op)
{
    const AccessPath *ap = result->access_path;
    if (!ap) return;

    /* First pass: max label display-width for column alignment.
       U+2514 U+2500 U+2500 space = 4 display cols but 10 UTF-8 bytes. */
    size_t col = 0;
    for (size_t i = 0; i < ap->count; i++) {
        size_t w = (i > 0 ? (i - 1) * 4 + 4 : 0)
                 + strlen(i == 0 ? "/" : basename_of(ap->components[i].path));
        if (w > col) col = w;
    }
    col += 2;

    bool past_block = false;
    for (size_t i = 0; i < ap->count; i++) {
        const PathComponent *comp = &ap->components[i];
        bool is_last  = (i == ap->count - 1);
        bool is_block = (result->allowed == false) && result->blocked_path
                        && strcmp(comp->path, result->blocked_path) == 0;

        const char *name = (i == 0) ? "/" : basename_of(comp->path);

        char label[256];
        if (i == 0) {
            label[0] = '/'; label[1] = '\0';
        } else {
            size_t off = 0;
            for (size_t j = 0; j < (i - 1) * 4; j++) label[off++] = ' ';
            snprintf(label + off, sizeof(label) - off,
                     "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 %s", name);
        }

        /* printf "%-*s" counts bytes; the tree connector is 10 bytes but 4 cols.
           Adding 6 to the width keeps every row visually aligned. */
        int pw = (int)(col + (i > 0 ? 6u : 0u));
        printf("  %-*s", pw, label);

        if (past_block) { putchar('\n'); continue; }
        if (is_block)     past_block = true;

        /* stat(2) failed: st fields are uninitialized (zeroed by calloc) */
        bool stat_failed = (comp->denial_reason == REASON_NOT_FOUND
                         || comp->denial_reason == REASON_NOT_TRAVERSABLE);
        if (stat_failed) { printf("(not found)\n"); continue; }

        char mstr[10], ubuf[16], gbuf[16];
        mode_str(comp->st.st_mode, mstr);
        const char *owner = uid_to_name(comp->st.st_uid, ubuf, sizeof(ubuf));
        const char *grp   = gid_to_name(comp->st.st_gid, gbuf, sizeof(gbuf));

        printf("%c%s  %-8s:%-8s  %s %s\n",
               file_type_char(comp->st.st_mode), mstr,
               owner, grp,
               is_last ? op_name(op) : "traverse",
               is_block ? "\xe2\x9c\x97" : "\xe2\x9c\x93");
    }
}

void render_result_text(const AccessResult *result, const User *user, AccessOperation op)
{
    const char *target = "?";
    if (result->access_path && result->access_path->count > 0)
        target = result->access_path->components[result->access_path->count - 1].path;

    putchar('\n');
    if (result->allowed) {
        printf("\xe2\x9c\x93  %s can %s %s\n",
               user->name, op_name(op), target);
    } else {
        printf("\xe2\x9c\x97  %s cannot %s %s\n",
               user->name, op_name(op), target);
        putchar('\n');
        if (result->blocked_path)
            printf("   blocked at  %s\n", result->blocked_path);
        print_reason(result);
    }
    putchar('\n');
    render_tree(result, op);
    putchar('\n');
}
