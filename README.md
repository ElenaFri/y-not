# y-not

[![CI](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml/badge.svg)](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ElenaFri/y-not/graph/badge.svg)](https://codecov.io/gh/ElenaFri/y-not)

> **Why can't I access this file?**

`y-not` is a Linux CLI that checks whether a named user has permission to read, write or attempt to execute a path, then explains the first blocking component, the permission decision it evaluated, and the least-privilege change that would grant access. It is designed to make a path-specific diagnosis easier to verify than manually combining `ls`, `namei`, `id` and `getfacl` output.

## A common diagnosis

The file itself looks readable to everyone:

```text
$ ls -l /srv/private/report.txt
-rw-r--r-- 1 alice alice 1200 ... /srv/private/report.txt
```

But the user cannot reach it because a parent directory is not searchable:

```text
$ y-not bob read /srv/private/report.txt

bob cannot read /srv/private/report.txt

  blocked at: /srv/private
  cause:      no traverse permission: not the owner and not in the directory's group
  proof:      Unix other bits: ---
  to allow:   grant only this user via ACL: sudo setfacl -m u:bob:x /srv/private

  /                           drwxr-xr-x  root:root   enter    ok
  └── srv                     drwxr-xr-x  root:root   enter    ok
      └── private             drwx------  alice:alice enter    BLOCKED
          └── report.txt
```

The trace shows the first component that prevents the requested operation. A directory must grant search (`x`) permission for each path component leading to the target; checking only the target's `ls -l` line misses that. The `cause:` line states the rule in plain words, `proof:` shows the exact permission bits it read (`Unix other bits: ---` here), and `to allow:` names the smallest change that would make the modeled verdict `allowed` - granting `bob` search on the parent directory through an ACL rather than opening it to everyone.

For a permission denied by an ACL, the `proof:` line shows the selected ACL source, its raw permissions, and (where applicable) the effective permissions after the ACL mask. This helps distinguish an entry that grants `rw-` from the effective `r--` result imposed by a mask.

## ACL mask: why an entry granting `rw-` can still deny writes

A named ACL entry can grant write permission while the ACL mask removes it from the effective permissions. This example requires the `acl` package and a local `nobody` account:

```sh
demo=$(mktemp -d)
trap 'rm -rf "$demo"' EXIT
mkdir "$demo/release"
printf 'customer_id,total\n42,125.00\n' > "$demo/release/report.csv"
ln -s "$demo/release/report.csv" "$demo/latest-report.csv"
chmod 755 "$demo" "$demo/release"
chmod 600 "$demo/release/report.csv"
setfacl -m u:nobody:rw-,m:r-- "$demo/release/report.csv"
y-not nobody write "$demo/latest-report.csv"
```

The ACL entry says `rw-`, but its mask limits the effective rights to `r--`. The `proof:` line names the selected entry and the mask that overrides it:

```text
nobody cannot write /tmp/demo/latest-report.csv

  blocked at: /tmp/demo/latest-report.csv
  cause:      an ACL entry grants you write, but the ACL mask removes it
  proof:      named ACL user entry: rw- & ACL mask r-- = r--
  to allow:   widen the ACL mask: sudo setfacl -m m::rw /tmp/demo/latest-report.csv

  /                                                              drwxr-xr-x  root:root   enter    ok
  └── tmp                                                        drwxrwxrwx  root:root   enter    ok
      └── demo                                                   drwxr-xr-x  elena_f:elena_f   enter    ok
          └── latest-report.csv -> /tmp/demo/release/report.csv  -rw-r-----  elena_f:elena_f   write    BLOCKED
```

The temporary path and owner/group names vary on your system. This checks the ACL metadata for `nobody`; y-not does not run the write operation as that account. Because y-not can tell the entry from the mask, the `to allow:` line points at the mask - the real blocker - instead of suggesting a redundant grant on an entry that already allows the write.

## Missing group membership: which group would help?

When a denial would be lifted by joining a group, y-not names every group whose effective permissions (after any ACL mask) would grant the operation, rather than guessing a single one. Here two named ACL groups could each grant read:

```sh
demo=$(mktemp -d)
trap 'rm -rf "$demo"' EXIT
chmod 755 "$demo"
printf 'secret\n' > "$demo/report.csv"
chmod 600 "$demo/report.csv"
setfacl -m g:mail:r,g:news:r,m:r "$demo/report.csv"
y-not nobody read "$demo/report.csv"
```

```text
nobody cannot read /tmp/demo/report.csv

  blocked at: /tmp/demo/report.csv
  cause:      not in any of the groups that would allow read: "mail", "news"
  proof:      ACL other entry: ---
  to allow:   add nobody to a group that grants it: sudo usermod -aG mail nobody, then log in again

  /                       drwxr-xr-x  root:root   enter    ok
  └── tmp                 drwxrwxrwx  root:root   enter    ok
      └── demo            drwxr-xr-x  elena_f:elena_f   enter    ok
          └── report.csv  -rw-r-----  elena_f:elena_f   read     BLOCKED
```

Only groups whose rights survive the ACL mask are listed, so the suggestion is actionable: joining any one of them would grant access. In JSON this appears as a `candidate_groups` array in the blocked component's `decision` object.

## Who can delete this file? Sticky directories

A world-writable directory looks like anyone may remove anything inside it, and the file's own bits look unremarkable:

```text
$ ls -ld /srv/uploads
drwxrwxrwt 2 alice alice 60 ... /srv/uploads
$ ls -l /srv/uploads/report.csv
-rw-r--r-- 1 alice alice 11 ... /srv/uploads/report.csv
```

But the trailing `t` is the sticky bit: it restricts removing an entry to the entry's owner, the directory's owner or root. So another user cannot delete the file even though the directory is writable to everyone:

```text
$ y-not bob delete /srv/uploads/report.csv

bob cannot delete /srv/uploads/report.csv

  blocked at: /srv/uploads/report.csv
  cause:      the parent directory has the sticky bit; you own neither the entry nor the directory
  proof:      sticky bit set; entry owner alice, directory owner alice
  to allow:   take ownership of the entry so the sticky directory lets you remove it: sudo chown bob /srv/uploads/report.csv

  /                       drwxr-xr-x  root:root     enter         ok
  └── srv                 drwxr-xr-x  root:root     enter         ok
      └── uploads         drwxrwxrwt  alice:alice   delete entry  ok
          └── report.csv  -rw-r--r--  alice:alice   enter         BLOCKED
```

Deleting a name is a property of the *parent* directory, not the file: `delete` checks write and search on the parent, then applies the sticky-bit ownership rule. The trace confirms `bob` may create entries in `uploads` (`delete entry  ok`) yet still cannot remove this one. Removal is governed by ownership of the entry (or the directory, or root) rather than a file permission bit, so the `to allow:` line names the least-privilege change that applies: transferring ownership of the entry to `bob`. In JSON the reason code is `sticky_bit`, `remediation` carries that same suggestion, and the target component gains an additive `entry_owner` field.

## When even root is refused: immutable and append-only attributes

Standard permissions say the owner may write this file, and `getfacl` shows no ACL that would change that:

```text
$ ls -l /etc/app/license.key
-rw-r--r-- 1 root root 48 ... /etc/app/license.key
```

Yet the write fails - and so does `rm`, even for root:

```text
$ sudo sh -c 'echo revoked >> /etc/app/license.key'
sh: /etc/app/license.key: Operation not permitted
```

Nothing in `ls -l` or `getfacl` explains this: the file carries the immutable inode attribute (`chattr +i`), set by an administrator or a hardening tool. y-not reads the attribute and names it as the blocker:

```text
$ y-not root write /etc/app/license.key

root cannot write /etc/app/license.key

  blocked at: /etc/app/license.key
  cause:      this file has the immutable attribute set; it cannot be changed or removed, not even by its owner or root
  proof:      the immutable attribute is set on this entry
  to allow:   clear the immutable attribute, a deliberate protection, to allow this: sudo chattr -i /etc/app/license.key

  /                      drwxr-xr-x  root:root   enter    ok
  └── etc                drwxr-xr-x  root:root   enter    ok
      └── app            drwxr-xr-x  root:root   enter    ok
          └── license.key  -rw-r--r--  root:root   write    BLOCKED  (attr: immutable)
```

The trace annotates the blocking component with `(attr: immutable)` - the detail `ls -l` cannot show. The immutable attribute overrides the owner and root alike, so y-not reports the denial even when the mode bits and ACLs would allow the write. The same rule governs deletion: an immutable file cannot be unlinked, and an immutable *directory* refuses to have entries added or removed.

A related attribute, append-only (`chattr +a`), blocks removal while still allowing writes that append. y-not is deliberate about the difference: a `write` to an append-only file is still reported as *allowed* (the kernel would accept the append), and only `delete` is blocked, with the entry annotated `(attr: append-only)`. In JSON the reason codes are `immutable` and `append_only`, the blocked component's `decision.source` is `fs_attr`, and `remediation` carries the matching `chattr` command.

## Install

Download the amd64 Debian package from [GitHub Releases](https://github.com/ElenaFri/y-not/releases) and let APT resolve the runtime library dependencies:

```sh
sudo apt install ./y-not_*.deb
```

The package's runtime dependencies are generated from the linked binary. The released package targets amd64 and requires a sufficiently recent Debian-family system; APT will report unmet library-version requirements if the host is too old. For other architectures, build from source.

## Usage

```sh
y-not [--json] USER OPERATION PATH
```

`OPERATION` is `read`/`r`, `write`/`w`, `execute`/`x` or `delete`/`d`. `--json` must appear first.

```sh
y-not alice read /srv/project/report.pdf
y-not --json alice write /srv/project
```

On a directory, `read` checks permission to list names, `execute` checks search/traversal, and `write` checks whether a directory entry can be created (both write and search are required). On a regular file, `execute` checks permission to attempt execution; it does not validate ELF/script format or check whether an interpreter or loader is available, so permission being allowed does not guarantee that launching the file will succeed. `delete` checks whether the named directory entry may be removed: the parent needs write and search permission, and a sticky directory additionally restricts removal to the entry owner, directory owner or root. `write` and `delete` also honor the immutable (`chattr +i`) and append-only (`chattr +a`) inode attributes, which override ownership. This models unlinking a name; it does not model renaming, removing a non-empty directory, `.`/`..` entries, or process-specific security policy.

The text output's `cause:`, `proof:` and `to allow:` lines correspond to the JSON `reason`, `decision` and `remediation` fields: the text uses plain-language labels for a human reader, while the JSON keys are a stable machine contract and do not change.

The JSON output has `schema_version: 1`. Its `trace` contains path components up to the first blocker and, for resolved components, a `decision` object with the permission source, raw/effective `rwx` bits and ACL mask details. When missing group membership explains a denial, `missing_group_gid` identifies one group whose permissions would grant the requested operation, and `candidate_groups` lists every such group (GID and name); for ACLs, the effective rights after the ACL mask are used. A top-level `mac` object reports SELinux/AppArmor status, `evaluated` (always `false`, since y-not never factors MAC into the verdict), `may_override_verdict` (true when an allowed verdict could still be denied by an active module) and a human-readable `warning` (or `null`). `reason` is a machine-readable reason code, and `remediation` is a human-readable suggestion of the least-privilege change that would grant access (or `null` when no permission change applies, such as a missing path). Exit status is 0 when allowed and 1 when denied, including unknown users and unresolved paths.

## What is checked

- Unix owner/group/other mode bits and supplementary group membership, including sticky-directory restrictions for `delete`.
- POSIX ACL owner, named-user, group and other entries, including the effective ACL mask.
- Root's DAC override behavior and grants listed in `/etc/security/capability.conf` for pam_cap.
- Read-only (`ro`) and `noexec` mount restrictions visible in y-not's mount namespace.
- Immutable (`chattr +i`) and append-only (`chattr +a`) inode attributes, which override the owner and root alike: immutable blocks write and delete, append-only blocks delete.
- The path trace, symbolic links, missing components, broken links and symlink loops.
- A suggested least-privilege remediation for the blocking component (`chmod`, group membership, an ACL grant or mask widening), or a note that a read-only/noexec mount, not a permission, is the blocker. Fixes that change a file you do not own are prefixed with `sudo`, since only the owner or root can apply them.

## Limits and scope

`y-not` is a diagnostic model, not a kernel access probe. It does not execute the requested operation as the target user, and its verdict does not account for every condition that can affect a real process.

- **SELinux and AppArmor do not change the verdict, but an active module is flagged.** y-not evaluates DAC/ACL only; it does not simulate SELinux policy, and AppArmor confinement is process/profile-specific and cannot be inferred from a user, operation and path alone. When the verdict is *allowed* and SELinux is enforcing or AppArmor has loaded profiles, y-not prints a prominent warning that the kernel may still deny a confined process (and sets `may_override_verdict` in the JSON `mac` object), so an "allowed" result is never mistaken for "unrestricted".
- **Capabilities are approximated.** pam_cap grants are read from `/etc/security/capability.conf`; file capabilities are displayed, but y-not does not simulate the effective capability set of an actual target process.
- **Mount flags are namespace-specific.** `ro` and `noexec` affect the modeled result; `nosuid` is reported as context only. A service or container in another mount namespace may see different flags.
- **Directory operations are specific.** `write` on a directory models creating an entry; `delete` models removing the named entry and includes sticky-bit ownership checks. Rename, removing a non-empty directory, ACL inheritance, and races between inspection and use are outside the model.
- **Inode attributes are read, with two honest caveats.** y-not reports the immutable and append-only attributes and lets them override the DAC/ACL verdict. Because append-only still permits appending, a `write` to an append-only file is reported as *allowed* - the kernel would accept the append - and only `delete` is blocked. Attributes are known only when y-not can open the inode to read them; if the open fails, they are omitted rather than guessed.
- **y-not inspects the path with its own privileges.** It reads each component's metadata as the user who runs `y-not`, not as the target user. If a parent directory denies the running process search, y-not cannot inspect what lies beneath it; it then reports that the path could not be inspected and the verdict is undetermined, rather than guessing. Run `y-not` as root (or as a user who can traverse the whole path) for a complete diagnosis.
- **Kernel and security-module behavior remains authoritative.** The actual result can also depend on the process credentials, namespaces, filesystem implementation and active security policy.

## Build and test

Build dependencies are a C compiler, GNU make, `libacl`, `libcap` and `libselinux` development headers/libraries.

```sh
make             # optimized binary ./y-not
make debug       # debug build with sanitizers
make check       # automated tests
sudo make install
sudo make uninstall
```

`make install` installs under `/usr/local` by default and needs permission to write there. Override the prefix for an unprivileged install, for example `make install PREFIX="$HOME/.local"`.

## Project and releases

- Source, issue tracker and changelog: [GitHub repository](https://github.com/ElenaFri/y-not)
- Published versions: [GitHub Releases](https://github.com/ElenaFri/y-not/releases)
- License: [LICENSE](LICENSE)
