#include "permissions/mode_bits.h"

/* Shift mode bits to the "other" position for uniform comparison. */
bool class_allows(mode_t mode, AccessOperation op, int shift)
{
    mode_t m = mode >> shift;
    switch (op)
    {
    case ACCESS_READ:
        return m & S_IROTH;
    case ACCESS_WRITE:
        return m & S_IWOTH;
    case ACCESS_EXECUTE:
        return m & S_IXOTH;
    default:
        return false;
    }
}

bool user_in_group(const User *user, gid_t gid)
{
    if (user->primary_gid == gid)
        return true;
    for (size_t i = 0; i < user->group_count; i++)
        if (user->groups[i] == gid)
            return true;
    return false;
}
