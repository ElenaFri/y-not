# y-not

A small Linux CLI that explains why a user can or cannot access a file or directory.

Instead of piecing together information from `ls`, `namei`, `id`, `getfacl` and other similar tools, `y-not` traces the access path and identifies what is blocking access.

> Early development

## Goals

- Explain effective file access on Linux
- Show where access is blocked
- Explain Unix owner/group/mode permissions
- Handle supplementary groups
- Support POSIX ACLs
- Provide clear, human-readable output
- Stay small, fast and dependency-light
