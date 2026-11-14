# pathaudit

**Find the PATH mistakes that let someone else's program run instead of yours.** Every command you type is looked up through the
directories in `$PATH`, first match wins. An empty or relative entry (a stray `:` or `.`) puts the current directory on that list, a writable
directory lets any other account plant a fake `ls` or `sudo`, and a writable directory placed before `/usr/bin` overrides the real ones.
pathaudit reads a PATH, checks each entry, and explains the risk and the fix. It only reads metadata; it never runs anything it finds.

Real output on a synthetic setup (a world-writable `shared` directory holding a fake `ls`, a `sys` directory with another `ls`, an empty entry,
a relative entry, a missing directory and a duplicate; the sandbox path is shortened to `DEMO`):

```
$ pathaudit --shadows --path "DEMO/shared::bin:DEMO/sys:DEMO/gone:DEMO/sys"
pathaudit: 6 PATH entries, 7 findings
HIGH   world-writable-dir     DEMO/shared
       mode 777
       risk: Anyone on the machine can add or replace programs here and have them run by whoever has this PATH.
       fix:  chmod o-w on the directory (or remove it from PATH).
HIGH   hijackable-shadow      DEMO/shared
       ls in untrusted dir hides the one in DEMO/sys
       risk: A command in an earlier, untrusted directory hides a command with the same name from a later directory.
       fix:  Delete or rename the shadowing file, fix the directory permissions, or reorder PATH.
HIGH   empty-entry            (empty)
       entry 1 is empty (means current directory)
       risk: An empty PATH entry means the current directory. Running any command in a directory an attacker can write to may run their file.
       fix:  Remove the empty entry (watch for leading, trailing or doubled colons).
HIGH   relative-entry         bin
       entry 2 is relative
       risk: A relative PATH entry resolves against whatever directory you are in, so a planted program there is run instead of the real one.
       fix:  Replace it with an absolute path or remove it.
MEDIUM group-writable-dir     DEMO/shared
       mode 777
       risk: Every member of the owning group can add or replace programs here.
       fix:  chmod g-w on the directory, or remove it from PATH.
LOW    missing-dir            DEMO/gone
       directory does not exist
       risk: A missing directory is dead weight, and if someone later creates it (or it is on a removable path) its contents gain PATH priority.
       fix:  Remove the entry, or create the directory with safe ownership.
LOW    duplicate-entry        DEMO/sys
       same directory as entry 3
       risk: The same directory appears more than once. Harmless by itself but it hides ordering mistakes and slows lookup.
       fix:  Keep only the first occurrence.

shadowed commands (first directory wins):
  ls: DEMO/shared  >  DEMO/sys
```

A clean PATH:

```
$ pathaudit --path DEMO/sys
pathaudit: 1 PATH entries, 0 findings
clean
```

One file, standard library only.

## What it checks

| Finding | Severity | Meaning |
|---|---|---|
| `empty-entry`, `relative-entry` | high | current directory is searched (`::`, leading/trailing `:`, `.`, `bin`, `~/bin` unexpanded) |
| `world-writable-dir` | high | anyone can plant programs (the sticky bit does not help here) |
| `group-writable-dir`, `untrusted-owner` | medium | group members, or an account that is not root or you, can plant programs |
| `writable-before-system` | high/medium | a writable or foreign-owned directory comes before `/bin`, `/sbin`, `/usr/bin` or `/usr/sbin` |
| `hijackable-shadow` | high | a command in an untrusted directory hides the same command in a later one |
| `symlinked-dir`, `missing-dir`, `not-a-dir`, `duplicate-entry` | low | hygiene issues; duplicates are found by resolved path |
| `shadowed-command` | info | same name in several trusted directories (shown with `--shadows`) |

## Usage

```bash
python3 pathaudit.py                       # audit $PATH
python3 pathaudit.py --path "/usr/bin:."    # audit a given string
python3 pathaudit.py --shadows             # also list shadowed commands
python3 pathaudit.py --json --fail-on high # machine-readable; only high findings fail
```

Exit codes: `0` clean (nothing at or above `--fail-on`, default `low`), `1` findings, `2` usage error.

## Limits

- It audits the PATH string and directory metadata. It does not look at file contents, signatures or hashes, so it cannot tell a genuine
  `ls` from a fake one.
- Only the last component of an entry is examined for ownership and mode; a writable or swappable *parent* directory, ACLs and extended
  attributes are not checked, and a symlinked parent such as `/bin -> usr/bin` is only reported when it is the entry itself.
- "Trusted owner" means root or the user running the audit. Group membership of the user is not considered.
- Shell aliases, functions, hashed commands and `~` expansion done by your shell are invisible to it; audit the expanded PATH.
- It looks at the PATH of the process that runs it, which may differ from another user's or a service's PATH. At most 1000 entries and
  50000 files per directory are examined.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
