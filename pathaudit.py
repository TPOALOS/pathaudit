#!/usr/bin/env python3
"""pathaudit: audit a PATH for hijack and hygiene problems. Read-only, never executes anything.

Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage/input error.
"""
import argparse
import json
import os
import stat
import sys

VERSION = "1.0.0"
SEVERITIES = ["info", "low", "medium", "high"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
SYSTEM_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin")
MAX_DIR_ENTRIES = 50000   # per-directory cap when listing commands
MAX_ENTRIES = 1000        # cap on PATH entries examined

RISK_FIX = {
    "empty-entry": (
        "An empty PATH entry means the current directory. Running any command in a directory an attacker can write to may run their file.",
        "Remove the empty entry (watch for leading, trailing or doubled colons)."),
    "relative-entry": (
        "A relative PATH entry resolves against whatever directory you are in, so a planted program there is run instead of the real one.",
        "Replace it with an absolute path or remove it."),
    "missing-dir": (
        "A missing directory is dead weight, and if someone later creates it (or it is on a removable path) its contents gain PATH priority.",
        "Remove the entry, or create the directory with safe ownership."),
    "not-a-dir": (
        "The entry exists but is not a directory, so it does nothing and hints at a stale or wrong configuration.",
        "Remove the entry."),
    "unreadable-dir": (
        "The directory could not be inspected, so it was not fully audited.",
        "Check permissions or run the audit as the same user that uses this PATH."),
    "world-writable-dir": (
        "Anyone on the machine can add or replace programs here and have them run by whoever has this PATH.",
        "chmod o-w on the directory (or remove it from PATH)."),
    "group-writable-dir": (
        "Every member of the owning group can add or replace programs here.",
        "chmod g-w on the directory, or remove it from PATH."),
    "untrusted-owner": (
        "The directory is owned by an account that is neither root nor you; that account can swap programs in it at will.",
        "chown it to root (system dirs) or yourself, or remove it from PATH."),
    "symlinked-dir": (
        "The entry is a symbolic link; whoever can retarget the link controls which programs are found.",
        "Use the real directory path in PATH and make sure the link and its parent are not writable by others."),
    "duplicate-entry": (
        "The same directory appears more than once. Harmless by itself but it hides ordering mistakes and slows lookup.",
        "Keep only the first occurrence."),
    "writable-before-system": (
        "A directory that unprivileged accounts can write to comes before a system directory, so a program planted there overrides ls, sudo, ssh and friends.",
        "Move the directory after the system directories, or make it non-writable for others."),
    "hijackable-shadow": (
        "A command in an earlier, untrusted directory hides a command with the same name from a later directory.",
        "Delete or rename the shadowing file, fix the directory permissions, or reorder PATH."),
    "shadowed-command": (
        "The same command name exists in several PATH directories; only the first one runs. Often legitimate (for example two Python installs) but worth knowing.",
        "Confirm the first one is intended; remove or reorder the others."),
}


def clean(s):
    """Make a string safe to print: escape control characters and undecodable bytes."""
    out = []
    for ch in str(s):
        if ch == "\\":
            out.append("\\\\")
        elif ch.isprintable():
            out.append(ch)
        else:
            o = ord(ch)
            out.append("\\x%02x" % o if o < 256 else "\\u%04x" % o if o < 0x10000 else "\\U%08x" % o)
    return "".join(out)


def make_finding(kind, severity, path, detail, **extra):
    risk, fix = RISK_FIX[kind]
    f = {"id": kind, "severity": severity, "entry": clean(path), "detail": clean(detail), "risk": risk, "fix": fix}
    f.update(extra)
    return f


def split_path(path_string):
    return path_string.split(os.pathsep)


def _dir_trust(st, trusted_uids):
    """Return (world_writable, group_writable, bad_owner) for a stat result."""
    mode = st.st_mode
    return bool(mode & stat.S_IWOTH), bool(mode & stat.S_IWGRP), st.st_uid not in trusted_uids


def _list_commands(directory):
    """Names of executable regular files in a directory. Uses stat only, never opens or runs them."""
    names = []
    try:
        with os.scandir(directory) as it:
            for n, e in enumerate(it):
                if n >= MAX_DIR_ENTRIES:
                    break
                try:
                    st = e.stat(follow_symlinks=True)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & 0o111:
                    names.append(e.name)
    except OSError:
        pass
    return names


def audit(path_string, current_uid=None, system_dirs=SYSTEM_DIRS, with_shadows=True):
    """Audit a PATH string. Returns {'entries': [...], 'findings': [...], 'shadows': [...]}."""
    if current_uid is None:
        current_uid = os.getuid() if hasattr(os, "getuid") else 0
    trusted = {0, current_uid}
    sysreal = set()
    for d in system_dirs:
        try:
            sysreal.add(os.path.realpath(d))
        except (OSError, ValueError):
            pass
    entries = split_path(path_string)[:MAX_ENTRIES]
    findings = []
    seen = {}
    info = []  # per entry: dict(index, entry, usable, real, untrusted, world)
    for idx, entry in enumerate(entries):
        rec = {"index": idx, "entry": entry, "usable": False, "real": None, "untrusted": False, "world": False}
        info.append(rec)
        if entry == "":
            findings.append(make_finding("empty-entry", "high", "(empty)", "entry %d is empty (means current directory)" % idx, index=idx))
            continue
        if "\0" in entry:
            findings.append(make_finding("missing-dir", "low", entry, "entry contains a NUL byte", index=idx))
            continue
        if not os.path.isabs(entry):
            findings.append(make_finding("relative-entry", "high", entry, "entry %d is relative" % idx, index=idx))
        try:
            lst = os.lstat(entry)
        except OSError:
            if os.path.isabs(entry):
                findings.append(make_finding("missing-dir", "low", entry, "directory does not exist", index=idx))
            continue
        islink = stat.S_ISLNK(lst.st_mode)
        try:
            st = os.stat(entry)
        except OSError:
            findings.append(make_finding("missing-dir", "low", entry,
                                         "symlink target does not exist" if islink else "cannot stat", index=idx))
            continue
        if not stat.S_ISDIR(st.st_mode):
            findings.append(make_finding("not-a-dir", "low", entry, "not a directory", index=idx))
            continue
        real = os.path.realpath(entry)
        rec["real"] = real
        rec["usable"] = True
        if islink:
            try:
                tgt = os.readlink(entry)
            except OSError:
                tgt = "?"
            findings.append(make_finding("symlinked-dir", "low", entry, "symlink to %s (resolves to %s)" % (tgt, real), index=idx))
        key = real
        if key in seen:
            findings.append(make_finding("duplicate-entry", "low", entry,
                                         "same directory as entry %d" % seen[key], index=idx))
            rec["usable"] = False  # do not double count for shadows
            continue
        seen[key] = idx
        world, group, badown = _dir_trust(st, trusted)
        rec["world"] = world
        rec["untrusted"] = world or group or badown
        if world:
            findings.append(make_finding("world-writable-dir", "high", entry, "mode %o" % stat.S_IMODE(st.st_mode), index=idx))
        if group:
            findings.append(make_finding("group-writable-dir", "medium", entry, "mode %o" % stat.S_IMODE(st.st_mode), index=idx))
        if badown:
            findings.append(make_finding("untrusted-owner", "medium", entry,
                                         "owned by uid %d (trusted: root or uid %d)" % (st.st_uid, current_uid), index=idx))
    # user-writable directory before a system dir
    first_sys = None
    for rec in info:
        if rec["usable"] and rec["real"] in sysreal:
            first_sys = rec["index"]
            break
    if first_sys is not None:
        for rec in info:
            if rec["index"] >= first_sys:
                break
            if rec["usable"] and rec["real"] not in sysreal and rec["untrusted"]:
                sev = "high" if rec["world"] else "medium"
                findings.append(make_finding("writable-before-system", sev, rec["entry"],
                                             "entry %d is writable/untrusted and precedes system directory entry %d" % (rec["index"], first_sys),
                                             index=rec["index"]))
    shadows = []
    if with_shadows:
        by_name = {}
        order = []
        for rec in info:
            if not rec["usable"]:
                continue
            for name in _list_commands(rec["real"]):
                if name not in by_name:
                    by_name[name] = []
                    order.append(name)
                by_name[name].append(rec)
        for name in sorted(order):
            recs = by_name[name]
            if len(recs) < 2:
                continue
            first = recs[0]
            shadows.append({"command": clean(name), "dirs": [clean(r["entry"]) for r in recs]})
            if first["untrusted"]:
                findings.append(make_finding("hijackable-shadow", "high", first["entry"],
                                             "%s in untrusted dir hides the one in %s" % (name, recs[1]["entry"]),
                                             command=clean(name), index=first["index"]))
            else:
                findings.append(make_finding("shadowed-command", "info", first["entry"],
                                             "%s here hides the copy in %s" % (name, recs[1]["entry"]),
                                             command=clean(name), index=first["index"]))
    return {"entries": [clean(e) for e in entries], "findings": findings, "shadows": shadows}


def filter_findings(result, show_shadows):
    if show_shadows:
        return result["findings"]
    return [f for f in result["findings"] if f["id"] != "shadowed-command"]


def render_text(path_string, result, findings, show_shadows):
    lines = ["pathaudit: %d PATH entries, %d findings" % (len(result["entries"]), len(findings))]
    order = sorted(findings, key=lambda f: (-RANK[f["severity"]], f.get("index", 0)))
    for f in order:
        lines.append("%-6s %-22s %s" % (f["severity"].upper(), f["id"], f["entry"]))
        lines.append("       %s" % f["detail"])
        lines.append("       risk: %s" % f["risk"])
        lines.append("       fix:  %s" % f["fix"])
    if show_shadows:
        lines.append("")
        if result["shadows"]:
            lines.append("shadowed commands (first directory wins):")
            for s in result["shadows"]:
                lines.append("  %s: %s" % (s["command"], "  >  ".join(s["dirs"])))
        else:
            lines.append("no shadowed commands")
    if not findings:
        lines.append("clean")
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(prog="pathaudit", description="Audit $PATH for hijack and hygiene problems (read-only).",
                                epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error.")
    p.add_argument("--path", help="PATH string to audit (default: $PATH)")
    p.add_argument("--shadows", action="store_true", help="also list commands shadowed by an earlier directory")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--fail-on", choices=SEVERITIES, default="low", help="lowest severity that causes exit 1 (default: low)")
    p.add_argument("--version", action="version", version="pathaudit " + VERSION)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    path_string = args.path if args.path is not None else os.environ.get("PATH")
    if path_string is None:
        print("pathaudit: no PATH set and --path not given", file=sys.stderr)
        return 2
    result = audit(path_string, with_shadows=True)
    findings = filter_findings(result, args.shadows)
    if args.json:
        out = {"tool": "pathaudit", "version": VERSION, "entries": result["entries"], "findings": findings}
        if args.shadows:
            out["shadows"] = result["shadows"]
        print(json.dumps(out, indent=2))
    else:
        print(render_text(path_string, result, findings, args.shadows))
    threshold = RANK[args.fail_on]
    return 1 if any(RANK[f["severity"]] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
