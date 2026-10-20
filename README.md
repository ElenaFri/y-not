# y-not

[![CI](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml/badge.svg)](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ElenaFri/y-not/graph/badge.svg)](https://codecov.io/gh/ElenaFri/y-not)

> **Why can't I access this file?**

`y-not` is a Linux CLI that checks whether a named user has permission to read, write or attempt to execute a path, then explains the first blocking component and the permission decision it evaluated. It is designed to make a path-specific diagnosis easier to verify than manually combining `ls`, `namei`, `id` and `getfacl` output.

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

  blocked at  /srv/private
  reason      no traverse permission: not the owner and not in the directory's group

  /                           drwxr-xr-x  root:root   enter    ok
  └── srv                     drwxr-xr-x  root:root   enter    ok
      └── private             drwx------  alice:alice enter    BLOCKED
          └── report.txt
```

The trace shows the first component that prevents the requested operation. A directory must grant search (`x`) permission for each path component leading to the target; checking only the target's `ls -l` line misses that.

For a permission denied by an ACL, the trace also shows the selected ACL source, its raw permissions, and (where applicable) the effective permissions after the ACL mask. This helps distinguish an entry that grants `rw-` from the effective `r--` result imposed by a mask.

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

The ACL entry says `rw-`, but its mask limits the effective rights to `r--`. The text output identifies the selected entry and the mask at the blocked file:

```text
nobody cannot write /tmp/demo/latest-report.csv

  blocked at  /tmp/demo/latest-report.csv
  reason      ACL entry found for you but it does not grant write permission

          └── latest-report.csv -> /tmp/demo/release/report.csv  -rw-r-----  alice:alice   write    BLOCKED
    decision    named ACL user entry: rw- & ACL mask r-- = r--
```

The temporary path and owner/group names vary on your system. This checks the ACL metadata for `nobody`; y-not does not run the write operation as that account.

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

`OPERATION` is `read`/`r`, `write`/`w` or `execute`/`x`. `--json` must appear first.

```sh
y-not alice read /srv/project/report.pdf
y-not --json alice write /srv/project
```

On a directory, `read` checks permission to list names, `execute` checks search/traversal, and `write` checks whether a directory entry can be created (both write and search are required). On a regular file, `execute` checks permission to attempt execution; it does not validate ELF/script format or check whether an interpreter or loader is available, so permission being allowed does not guarantee that launching the file will succeed. This generic check does not decide whether a particular directory entry may be removed or renamed: the entry's ownership and sticky-directory rules can affect that.

The JSON output has `schema_version: 1`. Its `trace` contains path components up to the first blocker and, for resolved components, a `decision` object with the permission source, raw/effective `rwx` bits and ACL mask details. When missing group membership explains a denial, `missing_group_gid` identifies one group whose permissions would grant the requested operation; for ACLs, the effective rights after the ACL mask are used. This identifies a relevant group, not every possible group membership. `reason` is a machine-readable reason code. Exit status is 0 when allowed and 1 when denied, including unknown users and unresolved paths.

## What is checked

- Unix owner/group/other mode bits and supplementary group membership.
- POSIX ACL owner, named-user, group and other entries, including the effective ACL mask.
- Root's DAC override behavior and grants listed in `/etc/security/capability.conf` for pam_cap.
- Read-only (`ro`) and `noexec` mount restrictions visible in y-not's mount namespace.
- The path trace, symbolic links, missing components, broken links and symlink loops.

## Limits and scope

`y-not` is a diagnostic model, not a kernel access probe. It does not execute the requested operation as the target user, and its verdict does not account for every condition that can affect a real process.

- **SELinux and AppArmor are informational only.** Their status/context may be displayed, but neither changes the allow/deny verdict. AppArmor confinement is process/profile-specific and cannot be inferred from a user, operation and path alone.
- **Capabilities are approximated.** pam_cap grants are read from `/etc/security/capability.conf`; file capabilities are displayed, but y-not does not simulate the effective capability set of an actual target process.
- **Mount flags are namespace-specific.** `ro` and `noexec` affect the modeled result; `nosuid` is reported as context only. A service or container in another mount namespace may see different flags.
- **Writes to directories mean creating a name.** Removal/rename checks, sticky-bit ownership rules, ACL inheritance, races between inspection and use, and application-specific behavior are outside this check.
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
