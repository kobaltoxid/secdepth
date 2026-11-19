import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secdepth" / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("resolve", SCRIPTS / "resolve.py")
resolve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resolve)
import inventory  # noqa: E402

LOCK = {
    "name": "app", "version": "1.0.0", "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "dependencies": {"a": "^1.0.0"}, "devDependencies": {"t": "^2.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "^1.0.0"}},
        "node_modules/b": {"version": "1.0.0"},
        "node_modules/t": {"version": "2.0.0", "dev": True, "dependencies": {"b": "^2.0.0"}},
        "node_modules/t/node_modules/b": {"version": "2.0.0", "dev": True},
        "node_modules/@scope/opt": {"version": "0.1.0", "optional": True},
        "packages/local": {"link": True, "resolved": "packages/local"},
    },
}


def write_project(files):
    tmp = tempfile.TemporaryDirectory()
    root = pathlib.Path(tmp.name)
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
    return tmp, root


class NpmComponentTests(unittest.TestCase):
    def setUp(self):
        self.root_id, comps, self.skipped = resolve.npm_components(LOCK, "package-lock.json", "exact")
        self.c = {x["id"]: x for x in comps}

    def test_root_and_direct_dependencies(self):
        self.assertEqual(self.root_id, "npm:app@1.0.0")
        self.assertEqual(self.c[self.root_id]["depends_on"], ["npm:a@1.0.0", "npm:t@2.0.0"])
        self.assertTrue(self.c["npm:a@1.0.0"]["direct"])
        self.assertFalse(self.c["npm:b@1.0.0"]["direct"])

    def test_nested_resolution_prefers_closest_node_modules(self):
        self.assertEqual(self.c["npm:a@1.0.0"]["depends_on"], ["npm:b@1.0.0"])
        self.assertEqual(self.c["npm:t@2.0.0"]["depends_on"], ["npm:b@2.0.0"])

    def test_scopes(self):
        self.assertEqual(self.c["npm:b@1.0.0"]["scope"], "runtime")
        self.assertEqual(self.c["npm:b@2.0.0"]["scope"], "dev")
        self.assertEqual(self.c["npm:@scope/opt@0.1.0"]["scope"], "optional")

    def test_purl_and_evidence(self):
        opt = self.c["npm:@scope/opt@0.1.0"]
        self.assertEqual(opt["purl"], "pkg:npm/%40scope/opt@0.1.0")
        self.assertEqual(opt["evidence"][0]["location"], "package-lock.json#node_modules/@scope/opt")

    def test_links_are_reported_not_dropped(self):
        self.assertEqual([p for p, _ in self.skipped], ["packages/local"])

    def test_lockfile_v1_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve.npm_components({"lockfileVersion": 1, "dependencies": {}}, "package-lock.json", "exact")


class ResolveProjectTests(unittest.TestCase):
    def test_committed_lockfile_gives_valid_inventory(self):
        tmp, root = write_project({"package.json": {"name": "app", "version": "1.0.0"}, "package-lock.json": LOCK})
        self.addCleanup(tmp.cleanup)
        data = resolve.resolve_project(root, generate=False)
        self.assertEqual(inventory.validate(data), [])
        self.assertTrue(data["coverage"]["complete"])
        self.assertIn("committed package-lock.json", data["resolution"][0])

    def test_unsupported_manifests_make_coverage_incomplete(self):
        tmp, root = write_project({"package.json": {"name": "app", "version": "1.0.0"}, "package-lock.json": LOCK,
                                   "tools/go.mod": "module x\n", "node_modules/x/go.mod": "ignored"})
        self.addCleanup(tmp.cleanup)
        data = resolve.resolve_project(root, generate=False)
        self.assertEqual(inventory.validate(data), [])
        self.assertFalse(data["coverage"]["complete"])
        paths = [e["path"] for e in data["coverage"]["entries"]]
        self.assertIn("tools/go.mod", paths)
        self.assertFalse(any(p.startswith("node_modules") for p in paths))

    def test_no_lockfile_without_generation_is_recorded(self):
        tmp, root = write_project({"package.json": {"name": "app", "version": "1.0.0"}})
        self.addCleanup(tmp.cleanup)
        data = resolve.resolve_project(root, generate=False)
        self.assertEqual(inventory.validate(data), [])
        self.assertEqual(data["coverage"]["entries"][0]["status"], "skipped")

    def test_directory_without_manifests(self):
        tmp, root = write_project({"README.md": "x"})
        self.addCleanup(tmp.cleanup)
        data = resolve.resolve_project(root, generate=False)
        self.assertEqual(inventory.validate(data), [])
        self.assertEqual(data["components"][0]["ecosystem"], "unknown")


if __name__ == "__main__":
    unittest.main()
