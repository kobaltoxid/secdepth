import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "install-user.sh"
SKILL = ROOT / "skills" / "secdepth"


class InstallTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = pathlib.Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def run_script(self, *args, config_dir=None):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR"}
        env["HOME"] = str(self.home)
        if config_dir is not None:
            env["CLAUDE_CONFIG_DIR"] = str(config_dir)
        return subprocess.run(["bash", str(SCRIPT), *args], env=env, capture_output=True, text=True)

    def assertLinked(self, target):
        self.assertTrue(target.is_symlink(), target)
        self.assertEqual(pathlib.Path(os.readlink(target)), SKILL)

    def test_default_installs_codex_and_claude(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLinked(self.home / ".agents/skills/secdepth")
        self.assertLinked(self.home / ".claude/skills/secdepth")

    def test_claude_config_dir_is_honored(self):
        config = self.home / ".claude-personal"
        result = self.run_script("claude", config_dir=config)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLinked(config / "skills/secdepth")
        self.assertFalse((self.home / ".claude").exists())
        self.assertFalse((self.home / ".agents").exists())

    def test_empty_claude_config_dir_falls_back(self):
        result = self.run_script("claude", config_dir="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLinked(self.home / ".claude/skills/secdepth")

    def test_codex_only(self):
        result = self.run_script("codex")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLinked(self.home / ".agents/skills/secdepth")
        self.assertFalse((self.home / ".claude").exists())

    def test_rerun_is_idempotent(self):
        self.run_script()
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Already linked", result.stdout)

    def test_refuses_to_replace_existing_entries(self):
        other = self.home / "other"
        other.mkdir()
        cases = {
            "symlink": lambda t: t.symlink_to(other),
            "directory": lambda t: t.mkdir(),
        }
        for name, make in cases.items():
            with self.subTest(name):
                target = self.home / ".claude/skills/secdepth"
                target.parent.mkdir(parents=True, exist_ok=True)
                make(target)
                result = self.run_script("claude")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Refusing to replace", result.stderr)
                target.unlink() if target.is_symlink() else target.rmdir()

    def test_usage_errors(self):
        for args in (("bogus",), ("codex", "claude")):
            with self.subTest(args=args):
                result = self.run_script(*args)
                self.assertEqual(result.returncode, 64)
                self.assertIn("Usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
