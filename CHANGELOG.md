# Changelog

All notable changes to `y-not` are documented here.

## v0.5.0 — SELinux and AppArmor (informational)

- SELinux: status (enforcing/permissive) and per-file security context, via libselinux
- AppArmor: status and loaded profile count, via `/sys/module/apparmor` and `/sys/kernel/security/apparmor`
- Neither changes the allow/deny verdict — see "Known limitations" in the README
- CI/CD: GitHub Actions (build, ASan/UBSan tests, Valgrind smoke test, coverage), Codecov and SonarCloud integration

## v0.4.0 — Capabilities

- `CAP_DAC_OVERRIDE` bypass via `/etc/security/capability.conf` (pam_cap), same behavior as root
- `CAP_DAC_READ_SEARCH` bypass: read and directory traversal only, not write or file execute
- First-matching-line-wins parser for `capability.conf` (per `capability.conf(5)`)
- File capabilities (`security.capability` xattr) detected via libcap and shown in the tree

## v0.3.0 — Symlinks and special files

- Symlink detection and display (`lstat` + `readlink`), shown as `name -> target` in the tree
- `REASON_BROKEN_SYMLINK` for links pointing to a non-existent target
- `REASON_SYMLINK_LOOP` for `ELOOP` (circular symlinks)
- Special files (character/block devices, FIFOs, sockets) rendered with the correct type letter
- Fixed a stack buffer overflow in `render_tree()` on deeply nested paths
- Fixed a path-normalization bug where a trailing `..` could leave a stray slash
- Refactored `permissions.c`: ACL evaluation extracted to `acl_eval.c`, shared mode-bit helpers to `mode_bits.c`

## v0.2.0 — POSIX ACLs

- ACL detection and evaluation via libacl (`acl_get_file`, `acl_get_entry`)
- Full POSIX ACL algorithm: owner ACL entry, named user/group entries with mask, other
- Human-readable explanation for ACL-based denials

## v0.1.0 — First working release

- Unix permission evaluation (owner / group / other)
- Supplementary groups
- Path traversal check (execute bit on each directory component)
- Human-readable explanation of the first blocking point
