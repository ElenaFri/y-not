# Changelog

All notable changes to `y-not` are documented here.

## v1.8.0 — Cross-check the verdict against the kernel

Don't take y-not's word for it: where it safely can, y-not asks the kernel too, and tells you when they disagree.

- Probe the kernel for a ground-truth check: fork, drop to the target identity and call `access(2)` on the resolved path, then report whether it agrees with the modeled verdict
- Add one text line — `verified:` when the kernel confirms, `MISMATCH:` when it disagrees (most often a security module such as SELinux or AppArmor denying a DAC/ACL-granted access), `unverified:` with an honest reason when it could not run — and an additive top-level `verification` object in JSON, keeping the schema version unchanged
- Skip the probe where it would mislead rather than confirm: when `access(2)` is blind to the real blocker (inode attributes, the sticky rule), when the path could not be fully resolved or traversed, and for `delete`; probing an account other than your own requires root
- Keep the cross-check strictly advisory — it never overrides the modeled verdict — and document it in the README and man page
- Internals (no behaviour change): cache per-user `capability.conf` lookups instead of re-reading the file on every permission check, and cut static-analysis maintainability debt

## v1.7.0 — Compare access across named accounts

See which of the accounts you name can perform the same operation on the same path.

- Add `--compare USER,USER,...` to report which explicitly listed accounts are allowed, without changing the primary user's verdict or exit status
- Add the `allowed for:` text line and an optional additive `allowed_for` array in JSON; keep the existing JSON schema version unchanged
- Document that comparisons are limited to the named accounts and share y-not's DAC/ACL and process-context limitations
- Harden account comparison bounds and use reentrant group-name lookup in explanations and remediation

## v1.6.0 — Explain who can delete a file

Answer a question `ls -l` cannot: why a user who can write and traverse a directory still cannot delete a file inside it.

- Add a `delete` (`d`) operation that evaluates removal of a directory entry: traverse and write on the parent directory, plus the sticky-bit rule
- Report `sticky_bit` when the parent directory is sticky and the user owns neither the entry nor the directory, with a proof naming both owners and a `to allow:` suggestion to take ownership of the entry — the classic `/tmp`-style case where write permission is not enough
- Reject deleting the filesystem root and the `.`/`..` entries with their own reasons, stating the refusal is a kernel rule rather than a permission
- Expose the deletion verdict in JSON (`sticky_bit`, `delete_root`, `delete_special` reasons; additive `entry_owner` on the target component) and document the operation and its scope in the README and man page

## v1.5.1 — Make the suggested fix runnable

Show `sudo` on a fix that needs it, so the suggestion actually works.

- Prefix a remediation with `sudo` when it changes a file the requesting user does not own (group, other and ACL denials): only the owner or root can run the `chmod`/`setfacl`, so the previous command would have failed with a permission error
- Leave owner denials as a plain `chmod u+…`, since the owner can apply it directly

## v1.5.0 — Actionable fixes and honest verdicts

Every denial now comes with the least-privilege fix, and y-not is honest about what it cannot decide.

- Add a `to allow:` line suggesting the smallest change that would grant access for the blocking component — a `chmod` bit, a group membership, an ACL grant, or an ACL mask widening — or a note that a read-only/`noexec` mount, not a permission, is the real blocker; exposed as `remediation` in JSON
- Warn when the DAC/ACL verdict is `allowed` but SELinux is enforcing or AppArmor has loaded profiles: the kernel may still deny a confined process, which y-not does not model. Reported as `may_override_verdict` and a human-readable `warning` in the JSON `mac` object
- Report honestly that a path could not be inspected when a parent directory denies y-not itself the traversal needed to resolve it, instead of guessing a verdict; suggest re-running as root
- Relabel the text denial summary with `cause:`, `proof:` and `to allow:`, and lift the permission proof into the summary block; the JSON field names (`reason`, `decision`, `remediation`) are unchanged

## v1.4.0 — List every group that would grant access

Turn a missing-group denial into actionable advice.

- Report every non-member group whose effective permissions (after any ACL mask) would grant the requested operation, instead of naming a single one
- Add a `candidate_groups` array (GID and name) to the JSON `decision`; keep `missing_group_gid` for compatibility
- Document the multi-group diagnosis in the README and man page

## v1.3.1 — Clarify execute permission checks

Clarify that `execute` checks permissions, not executable format.

- State explicitly when a regular file lacks execute permission for the user
- Document that y-not does not validate executable formats or interpreter/loader availability

## v1.3.0 — Permission decision transparency

Make permission denials easier to understand and act on.

- Show the permission source and raw/effective `rwx` details in access traces, including ACL mask effects
- Identify one missing Unix or ACL group whose effective permissions would grant the requested operation; expose its GID as `missing_group_gid` in JSON
- Refresh the README diagnosis examples and isolate coverage builds from the normal build artifacts

## v1.2.0 — Path and mount access accuracy

More accurate Linux access checks across symlink paths, directory writes, and mount restrictions.

- Preserve lexical `.` and `..` path components so the kernel resolves them after following preceding symlinks; reject empty pathnames and honor trailing-slash directory requirements
- Require both write and traversal permission to create entries in a directory; report traversal denials distinctly and correctly model root's directory-search bypass
- Include read-only and `noexec` mount restrictions in access decisions; report `nosuid` as context, using flags visible in y-not's mount namespace
- Add a CI integration job that builds the Debian package, removes build dependencies, installs and exercises the package, then verifies removal
- Document the scope and limitations of directory operations, mount namespaces, and mount flags

## v1.1.1 — Fixes

Reliability fixes for permission explanations and Debian package delivery.

- Fixed the denial message for a blocked parent directory: it now says "traverse" (matching the tree's `enter` column and the JSON trace's `"checked": "enter"`) instead of claiming a missing read/write bit
- Debian package: generate versioned runtime dependencies with `dpkg-shlibdeps`; ship a policy-valid `changelog.Debian.gz`; keep the rich upstream notes as `changelog.gz`; honour `SOURCE_DATE_EPOCH` for reproducible builds; single-source the maintainer field
- Release workflow now triggers on every `vX.Y.Z` tag, not only major versions, so each published version ships a downloadable `.deb`

## v1.1.0 — JSON output

JSON output.

- `--json` flag (must come first): emits a machine-readable document instead of text, for scripts/CI
- Stable `reason` machine code plus a human `explanation` string for every denial
- `trace` array mirrors the text renderer: stops at (and includes) the blocked component, never reveals what's past it
- Always emits valid JSON, even for an unknown user or an unresolvable path
- Fixed a latent stdio-buffering bug in the test harness: `fflush(stdout)` must happen before redirecting fd 1, or already-buffered output can bleed into the wrong stream
- Fixed `Installed-Size` in the `.deb` control file: it was computed via `$(shell ...)` inside a Make recipe, which evaluates too early (before the package staging directory exists) and silently produced an empty field on a clean build
- Reorganized `src/`/`include/` into `resolve/`, `permissions/`, `context/`, `render/` subdirectories, grouped by responsibility rather than kept flat

## v1.0.0 — Stable CLI, packaging

A stable command-line interface and Debian package release.

- `--version` and `--help`/`-h` flags
- Man page (`man/y-not.1`), installed by `make install`
- `.deb` packaging (`make deb`): stripped binary, compressed man page, copyright/changelog, validated with `lintian` and a real install/upgrade/remove cycle
- Fixed a Makefile bug where bumping `VERSION` without `make clean` could ship a binary reporting the wrong version
- "Known limitations" section in the README, documenting the ACL mask nuance, untested OOM/TOCTOU paths, and CI running as root
- CI/CD hardening: GitHub Actions pinned to full commit SHAs (Dependabot keeps them updated), `.deb` published on major-version tags via a dedicated release workflow

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
