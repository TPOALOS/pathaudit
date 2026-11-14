import contextlib
import io
import json
import os
import stat
import tempfile
import unittest

import pathaudit as pa


def mkdir(base, name, mode=0o755):
    p = os.path.join(base, name)
    os.makedirs(p, exist_ok=True)
    os.chmod(p, mode)
    return os.path.realpath(p)


def touch_exe(d, name, mode=0o755):
    p = os.path.join(d, name)
    with open(p, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(p, mode)
    return p


def ids(result):
    return [f["id"] for f in result["findings"]]


def run_cli(args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = pa.main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = os.path.realpath(self._td.name)

    def audit(self, *dirs, **kw):
        kw.setdefault("system_dirs", ())
        return pa.audit(os.pathsep.join(dirs), **kw)


class TestEmptyAndRelative(Base):
    def test_empty_entry_flagged(self):
        d = mkdir(self.tmp, "a")
        r = self.audit(d, "")
        self.assertIn("empty-entry", ids(r))

    def test_leading_colon(self):
        d = mkdir(self.tmp, "a")
        self.assertIn("empty-entry", ids(self.audit("", d)))

    def test_trailing_colon(self):
        d = mkdir(self.tmp, "a")
        self.assertIn("empty-entry", ids(self.audit(d, "")))

    def test_double_colon(self):
        d = mkdir(self.tmp, "a")
        self.assertIn("empty-entry", ids(self.audit(d, "", d + "/")))

    def test_empty_path_string(self):
        self.assertIn("empty-entry", ids(pa.audit("", system_dirs=())))

    def test_dot_is_relative(self):
        self.assertIn("relative-entry", ids(self.audit(".")))

    def test_relative_name(self):
        self.assertIn("relative-entry", ids(self.audit("bin")))

    def test_relative_dotdot(self):
        self.assertIn("relative-entry", ids(self.audit("../bin")))

    def test_tilde_literal_relative(self):
        self.assertIn("relative-entry", ids(self.audit("~/bin")))

    def test_relative_is_high(self):
        f = [x for x in self.audit(".")["findings"] if x["id"] == "relative-entry"][0]
        self.assertEqual(f["severity"], "high")

    def test_absolute_not_relative(self):
        d = mkdir(self.tmp, "a")
        self.assertNotIn("relative-entry", ids(self.audit(d)))


class TestExistenceAndType(Base):
    def test_missing_dir(self):
        r = self.audit(os.path.join(self.tmp, "nope"))
        self.assertIn("missing-dir", ids(r))

    def test_file_not_dir(self):
        p = touch_exe(self.tmp, "afile")
        self.assertIn("not-a-dir", ids(self.audit(p)))

    def test_dangling_symlink_entry(self):
        l = os.path.join(self.tmp, "lnk")
        os.symlink(os.path.join(self.tmp, "gone"), l)
        self.assertIn("missing-dir", ids(self.audit(l)))

    def test_nul_byte_entry_no_crash(self):
        r = self.audit("/usr/bin\0evil")
        self.assertIn("missing-dir", ids(r))

    def test_clean_dir_no_findings(self):
        d = mkdir(self.tmp, "ok", 0o755)
        self.assertEqual(ids(self.audit(d)), [])


class TestPermissions(Base):
    def test_world_writable(self):
        d = mkdir(self.tmp, "w", 0o777)
        self.assertIn("world-writable-dir", ids(self.audit(d)))

    def test_world_writable_high(self):
        d = mkdir(self.tmp, "w", 0o757)
        f = [x for x in self.audit(d)["findings"] if x["id"] == "world-writable-dir"][0]
        self.assertEqual(f["severity"], "high")

    def test_sticky_world_writable_still_flagged(self):
        d = mkdir(self.tmp, "t", 0o1777)
        self.assertIn("world-writable-dir", ids(self.audit(d)))

    def test_group_writable(self):
        d = mkdir(self.tmp, "g", 0o775)
        r = self.audit(d)
        self.assertIn("group-writable-dir", ids(r))
        self.assertNotIn("world-writable-dir", ids(r))

    def test_mode_755_clean(self):
        d = mkdir(self.tmp, "n", 0o755)
        r = self.audit(d)
        self.assertNotIn("group-writable-dir", ids(r))

    def test_untrusted_owner(self):
        d = mkdir(self.tmp, "o")
        r = self.audit(d, current_uid=-12345)
        self.assertIn("untrusted-owner", ids(r))

    def test_own_dir_trusted(self):
        d = mkdir(self.tmp, "o")
        r = self.audit(d, current_uid=os.getuid())
        self.assertNotIn("untrusted-owner", ids(r))

    def test_finding_has_risk_and_fix(self):
        d = mkdir(self.tmp, "w", 0o777)
        for f in self.audit(d)["findings"]:
            self.assertTrue(f["risk"])
            self.assertTrue(f["fix"])


class TestSymlinksAndDuplicates(Base):
    def test_symlinked_dir(self):
        real = mkdir(self.tmp, "real")
        l = os.path.join(self.tmp, "link")
        os.symlink(real, l)
        r = self.audit(l)
        self.assertIn("symlinked-dir", ids(r))

    def test_symlinked_dir_perms_checked_on_target(self):
        real = mkdir(self.tmp, "real", 0o777)
        l = os.path.join(self.tmp, "link")
        os.symlink(real, l)
        self.assertIn("world-writable-dir", ids(self.audit(l)))

    def test_plain_dir_not_symlinked(self):
        d = mkdir(self.tmp, "p")
        self.assertNotIn("symlinked-dir", ids(self.audit(d)))

    def test_duplicate_exact(self):
        d = mkdir(self.tmp, "d")
        self.assertIn("duplicate-entry", ids(self.audit(d, d)))

    def test_duplicate_trailing_slash(self):
        d = mkdir(self.tmp, "d")
        self.assertIn("duplicate-entry", ids(self.audit(d, d + "/")))

    def test_duplicate_via_symlink(self):
        d = mkdir(self.tmp, "d")
        l = os.path.join(self.tmp, "l")
        os.symlink(d, l)
        self.assertIn("duplicate-entry", ids(self.audit(d, l)))

    def test_no_dup_for_different_dirs(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        self.assertNotIn("duplicate-entry", ids(self.audit(a, b)))


class TestShadows(Base):
    def test_shadow_detected(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "tool")
        touch_exe(b, "tool")
        r = self.audit(a, b)
        self.assertEqual(len(r["shadows"]), 1)
        self.assertEqual(r["shadows"][0]["command"], "tool")
        self.assertEqual(r["shadows"][0]["dirs"], [a, b])

    def test_shadow_info_when_trusted(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "tool")
        touch_exe(b, "tool")
        f = self.audit(a, b)["findings"]
        self.assertEqual([x["severity"] for x in f if x["id"] == "shadowed-command"], ["info"])

    def test_hijackable_shadow_high(self):
        a, b = mkdir(self.tmp, "a", 0o777), mkdir(self.tmp, "b")
        touch_exe(a, "ls")
        touch_exe(b, "ls")
        r = self.audit(a, b)
        self.assertIn("hijackable-shadow", ids(r))

    def test_non_executable_ignored(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "tool", 0o644)
        touch_exe(b, "tool")
        self.assertEqual(self.audit(a, b)["shadows"], [])

    def test_directory_named_like_command_ignored(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        os.mkdir(os.path.join(a, "tool"))
        touch_exe(b, "tool")
        self.assertEqual(self.audit(a, b)["shadows"], [])

    def test_duplicate_dir_not_a_shadow(self):
        a = mkdir(self.tmp, "a")
        touch_exe(a, "tool")
        self.assertEqual(self.audit(a, a)["shadows"], [])

    def test_control_char_command_name_escaped(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "ev\x1b[31mil")
        touch_exe(b, "ev\x1b[31mil")
        r = self.audit(a, b)
        self.assertNotIn("\x1b", json.dumps(r))
        self.assertIn("\\x1b", r["shadows"][0]["command"])

    def test_shadow_does_not_execute(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        marker = os.path.join(self.tmp, "ran")
        for d in (a, b):
            p = os.path.join(d, "tool")
            with open(p, "w") as f:
                f.write("#!/bin/sh\ntouch %s\n" % marker)
            os.chmod(p, 0o755)
        self.audit(a, b)
        self.assertFalse(os.path.exists(marker))

    def test_without_shadows_flag_hides_info(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "tool")
        touch_exe(b, "tool")
        code, out, _ = run_cli(["--path", a + ":" + b])
        self.assertEqual(code, 0)
        self.assertNotIn("shadowed commands", out)


class TestWritableBeforeSystem(Base):
    def test_world_writable_before_system(self):
        w = mkdir(self.tmp, "w", 0o777)
        sysd = mkdir(self.tmp, "sys")
        r = self.audit(w, sysd, system_dirs=(sysd,))
        f = [x for x in r["findings"] if x["id"] == "writable-before-system"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], "high")

    def test_after_system_not_flagged(self):
        w = mkdir(self.tmp, "w", 0o777)
        sysd = mkdir(self.tmp, "sys")
        r = self.audit(sysd, w, system_dirs=(sysd,))
        self.assertNotIn("writable-before-system", ids(r))

    def test_group_writable_medium(self):
        w = mkdir(self.tmp, "w", 0o775)
        sysd = mkdir(self.tmp, "sys")
        r = self.audit(w, sysd, system_dirs=(sysd,))
        f = [x for x in r["findings"] if x["id"] == "writable-before-system"]
        self.assertEqual(f[0]["severity"], "medium")

    def test_untrusted_owner_before_system(self):
        w = mkdir(self.tmp, "w")
        sysd = mkdir(self.tmp, "sys")
        r = self.audit(w, sysd, system_dirs=(sysd,), current_uid=-5)
        self.assertIn("writable-before-system", ids(r))

    def test_no_system_dir_in_path_no_finding(self):
        w = mkdir(self.tmp, "w", 0o777)
        r = self.audit(w, system_dirs=(os.path.join(self.tmp, "absent"),))
        self.assertNotIn("writable-before-system", ids(r))

    def test_default_system_dirs_constant(self):
        self.assertIn("/usr/bin", pa.SYSTEM_DIRS)


class TestOutputSafety(Base):
    def test_clean_escapes_controls(self):
        self.assertEqual(pa.clean("a\nb\x07"), "a\\x0ab\\x07")

    def test_clean_escapes_backslash(self):
        self.assertEqual(pa.clean("a\\b"), "a\\\\b")

    def test_clean_surrogate(self):
        self.assertNotIn("\udcff", pa.clean("x\udcff"))

    def test_hostile_entry_name_in_output(self):
        d = os.path.join(self.tmp, "ev\x1b]0;pwn\x07il")
        r = self.audit(d)
        self.assertNotIn("\x1b", json.dumps(r))
        code, out, _ = run_cli(["--path", d])
        self.assertNotIn("\x1b", out)

    def test_huge_path_capped(self):
        p = os.pathsep.join(["/nonexistent_x%d" % i for i in range(pa.MAX_ENTRIES + 500)])
        r = pa.audit(p, system_dirs=(), with_shadows=False)
        self.assertEqual(len(r["entries"]), pa.MAX_ENTRIES)

    def test_binary_ish_path_no_crash(self):
        pa.audit("\x00\xff:\udcff", system_dirs=())


class TestCLI(Base):
    def test_clean_exit_0(self):
        d = mkdir(self.tmp, "ok")
        code, out, _ = run_cli(["--path", d])
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_findings_exit_1(self):
        code, _, _ = run_cli(["--path", "."])
        self.assertEqual(code, 1)

    def test_fail_on_high_ignores_low(self):
        code, _, _ = run_cli(["--path", os.path.join(self.tmp, "gone"), "--fail-on", "high"])
        self.assertEqual(code, 0)

    def test_fail_on_high_catches_high(self):
        code, _, _ = run_cli(["--path", "", "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_bad_option_exit_2(self):
        code, _, _ = run_cli(["--bogus"])
        self.assertEqual(code, 2)

    def test_bad_fail_on_exit_2(self):
        code, _, _ = run_cli(["--fail-on", "nope"])
        self.assertEqual(code, 2)

    def test_json_output_valid(self):
        d = mkdir(self.tmp, "w", 0o777)
        code, out, _ = run_cli(["--path", d, "--json"])
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["tool"], "pathaudit")
        self.assertTrue(data["findings"])

    def test_json_shadows_key_only_with_flag(self):
        d = mkdir(self.tmp, "ok")
        _, out, _ = run_cli(["--path", d, "--json"])
        self.assertNotIn("shadows", json.loads(out))
        _, out, _ = run_cli(["--path", d, "--json", "--shadows"])
        self.assertIn("shadows", json.loads(out))

    def test_shadows_flag_lists(self):
        a, b = mkdir(self.tmp, "a"), mkdir(self.tmp, "b")
        touch_exe(a, "tool")
        touch_exe(b, "tool")
        code, out, _ = run_cli(["--path", a + ":" + b, "--shadows"])
        self.assertIn("tool:", out)

    def test_env_path_used(self):
        d = mkdir(self.tmp, "ok")
        old = os.environ.get("PATH")
        os.environ["PATH"] = d
        try:
            code, out, _ = run_cli([])
        finally:
            os.environ["PATH"] = old
        self.assertEqual(code, 0)

    def test_text_has_risk_and_fix(self):
        _, out, _ = run_cli(["--path", "."])
        self.assertIn("risk:", out)
        self.assertIn("fix:", out)

    def test_read_only_no_changes(self):
        d = mkdir(self.tmp, "w", 0o777)
        before = sorted(os.listdir(d))
        mode = stat.S_IMODE(os.stat(d).st_mode)
        run_cli(["--path", d])
        self.assertEqual(sorted(os.listdir(d)), before)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), mode)


if __name__ == "__main__":
    unittest.main()
