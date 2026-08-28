# y-not

A small Linux CLI that explains why a user can or cannot access a file or directory.

Instead of piecing together information from `ls`, `namei`, `id`, `getfacl` and other similar tools, `y-not` traces the access path and identifies what is blocking access.

> Early development

## Usage

```sh
y-not USER OPERATION PATH
```

`OPERATION` must be `read`, `write`, or `execute`.

## Architecture

The engine never knows what's on the terminal. It receives a user, an operation and a path, and produces a structured result. The renderer turns that result into human-readable output.

```text
src/
├── main.c         argument parsing, entry point
├── user.c         resolve uid, primary gid and supplementary groups
├── path.c         decompose path into components, stat(2) each one
├── permissions.c  evaluate Unix mode bits against a user
├── access.c       orchestrate the above, return the first blocking point
└── output.c       render AccessResult as text (or JSON later)
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
| v0.4 | capabilities |
| v0.5 | SELinux / AppArmor |

## Goals

- Explain effective file access on Linux
- Show where access is blocked
- Explain Unix owner/group/mode permissions
- Handle supplementary groups
- Support POSIX ACLs
- Provide clear, human-readable output
- Stay small, fast and dependency-light
