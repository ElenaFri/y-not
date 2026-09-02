# y-not

A small Linux CLI that explains why a user can or cannot access a file or directory.

Instead of piecing together information from `ls`, `namei`, `id`, `getfacl` and other similar tools, `y-not` traces the access path and identifies what is blocking access.

## Usage

```sh
y-not USER OPERATION PATH
```

`OPERATION` accepts `read`/`r`, `write`/`w`, or `execute`/`x`.

## Build & test

```sh
make          # release build ./y-not
make debug    # with ASan/UBSan
make check    # run all unit tests (always built with ASan/UBSan)
make install  # install to /usr/local/bin  (PREFIX= to override)
```

## Architecture

The engine never knows what's on the terminal. It receives a user, an operation and a path, and produces a structured result. The renderer turns that result into human-readable output.

```text
src/
├── main.c          argument parsing, entry point
├── user.c          resolve uid, primary gid and supplementary groups
├── path.c          decompose path into components, stat(2)/lstat(2) each one
├── mode_bits.c     shared owner/group/other bit checks and group membership
├── permissions.c   dispatch: root/capability bypass, ACL, or plain Unix bits
├── acl_eval.c      full POSIX ACL evaluation algorithm
├── capabilities.c  CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH via capability.conf
├── selinux_info.c  SELinux status and per-file context (informational)
├── apparmor_info.c AppArmor status and loaded profile count (informational)
├── access.c        orchestrate the above, return the first blocking point
└── output.c        render AccessResult as text (or JSON later)
```

The key invariant: `check_access()` builds a complete `AccessResult`(with
`blocked_path` and `reason`) before any output is produced. Tests can
therefore assert on the result directly, without parsing terminal output.

### Roadmap

| Version | Scope |
| --------- | ------- |
| v0.1 | owner / group / other, supplementary groups, path traversal |
| v0.2 | POSIX ACLs |
| v0.3 | symlinks, special files |
| v0.4 | capabilities (CAP_DAC_OVERRIDE/CAP_DAC_READ_SEARCH bypass, file capabilities display) |
| v0.5 | SELinux (status + per-file context, informational) and AppArmor (status + profile count, informational) |

## Goals

- Explain effective file access on Linux
- Show where access is blocked
- Explain Unix owner/group/mode permissions
- Handle supplementary groups
- Support POSIX ACLs
- Provide clear, human-readable output
- Stay small, fast and dependency-light
