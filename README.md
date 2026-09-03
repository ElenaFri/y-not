# y-not

[![CI](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml/badge.svg)](https://github.com/ElenaFri/y-not/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ElenaFri/y-not/graph/badge.svg)](https://codecov.io/gh/ElenaFri/y-not)

A small Linux CLI that explains why a user can or cannot access a file or directory.

Instead of piecing together information from `ls`, `namei`, `id`, `getfacl` and other similar tools, `y-not` traces the access path and identifies what is blocking access.

## Usage

```sh
y-not [--json] USER OPERATION PATH
```

`OPERATION` accepts `read`/`r`, `write`/`w`, or `execute`/`x`. `--json` (must
come first) emits a machine-readable JSON document instead of text — see
[JSON output](#json-output) below.

## Build & test

```sh
make          # release build ./y-not
make debug    # with ASan/UBSan
make check    # run all unit tests (always built with ASan/UBSan)
make install  # install to /usr/local/bin  (PREFIX= to override)
```

## JSON output

`y-not --json USER OPERATION PATH` prints a document instead of text:

```json
{
  "schema_version": 1,
  "user": "alice",
  "operation": "write",
  "path": "/srv/project/report.pdf",
  "allowed": false,
  "reason": "group_missing",
  "explanation": "not in group \"developers\" (which would allow write)",
  "blocked_at": "/srv/project",
  "trace": [ ... ]
}
```

`reason` is a stable machine code (see `reason_code()` in `src/json_output.c`
for the full list); `explanation` is the same human sentence the text
renderer would print. `trace` lists each path component up to and including
the blocked one — nothing past that point is revealed, matching the text
renderer. The exit code contract (0 allowed / 1 denied) is unchanged, and
`--json` always emits a valid document, even for an unknown user or a path
that couldn't be resolved at all.

## Architecture

The engine never knows what's on the terminal. It receives a user, an operation and a path, and produces a structured result. The renderer turns that result into human-readable output.

```text
src/
├── main.c              argument parsing, entry point
├── access.c            orchestrate the modules below, return the first blocking point
├── resolve/            turn raw strings into structured data
│   ├── user.c              resolve uid, primary gid and supplementary groups
│   └── path.c              decompose path into components, stat(2)/lstat(2) each one
├── permissions/        the access-decision engine
│   ├── mode_bits.c         shared owner/group/other bit checks and group membership
│   ├── permissions.c       dispatch: root/capability bypass, ACL, or plain Unix bits
│   ├── acl_eval.c          full POSIX ACL evaluation algorithm
│   └── capabilities.c      CAP_DAC_OVERRIDE / CAP_DAC_READ_SEARCH via capability.conf
├── context/            informational only - never changes the verdict
│   ├── selinux_info.c      SELinux status and per-file context
│   └── apparmor_info.c     AppArmor status and loaded profile count
└── render/             turn an AccessResult into output
    ├── output.c            human-readable text
    └── json_output.c       JSON (schema_version 1)
```

`include/` mirrors this layout one-to-one.

The key invariant: `check_access()` builds a complete `AccessResult`(with
`blocked_path` and `reason`) before any output is produced. Tests can
therefore assert on the result directly, without parsing terminal output.

## Goals

- Explain effective file access on Linux
- Show where access is blocked
- Explain Unix owner/group/mode permissions
- Handle supplementary groups
- Support POSIX ACLs
- Provide clear, human-readable output
- Stay small, fast and dependency-light

## Known limitations

- **SELinux/AppArmor are informational only.** Neither changes the allow/deny
  verdict. AppArmor confines programs, not users, so a per-file check does not
  fit the `USER OPERATION PATH` model.
- **ACL mask vs. mode bits.** When a file has an extended ACL, the group bits
  reported by `stat()` mirror the ACL mask, not the owning group's real
  permissions. The `GROUP_MISSING` fallback reason uses those bits as a
  heuristic, which can be misleading in rare ACL configurations.
- **`getgrouplist()` growth loop is untested.** Simulating a user in more than
  64 groups would require a real system account; not exercised in CI.
- **Allocation-failure paths are untested.** `malloc`/`strdup`/`realloc`
  failures throughout the codebase are handled but not exercised, since
  reliably simulating OOM without a fragile allocator wrapper isn't practical.
  A `getcwd()` failure and a symlink-removed-mid-`lstat()`/`stat()` race in
  `path.c` fall in the same category.
- **CI runs as root** (see `.github/workflows/ci.yml`), which flips which
  conditional tests execute compared to a typical non-root development
  machine. Codecov's reported percentage may differ slightly from a local run.
