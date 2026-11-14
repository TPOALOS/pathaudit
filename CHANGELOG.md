# Changelog

## 1.0.0

First release.

- Audits `$PATH` or `--path`: empty and relative entries, missing directories, group/world-writable or foreign-owned directories, symlinked directories, duplicates
- Detects commands shadowed by an earlier directory (`--shadows`) and flags a writable directory placed before a system directory
- Every finding explains the risk and the fix; `--json`, `--fail-on`; read-only and never executes anything
