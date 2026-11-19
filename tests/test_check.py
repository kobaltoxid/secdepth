import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secdepth" / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("check", SCRIPTS / "check.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)
import inventory  # noqa: E402

FILES = {
    "package.json": json.dumps({"name": "lib", "version": "1.0.0", "files": ["index.js", "lib/"]}),
    "index.js": "module.exports = require('./lib/app');\n",
    "lib/app.js": "var qs = require('qs');\n// qs.stringify(x) in a comment\nvar out = JSON.stringify(x);\n"
                  "exports.parse = function (s) { return qs.parse(s); };\n"
                  "res.redirect = function redirect(url) {};\n",
    "test/app.test.js": "const mocha = require('mocha');\nrequire('qs');\n",
    "examples/demo.js": "import chalk from 'chalk';\n",
}


def comp(cid, name, scope="runtime", depends_on=(), root=False, direct=None):
    return {"id": cid, "name": name, "ecosystem": "npm", "version": cid.rsplit("@", 1)[1], "scope": scope, "root": root,
            "direct": direct, "depends_on": list(depends_on),
            "evidence": [{"identifier": "t", "location": "t", "confidence": "exact"}]}


def inventory_data():
    data = inventory.new_inventory("t", "0", "source", ".", "npm:lib@1.0.0")
    data["components"] = [
        comp("npm:lib@1.0.0", "lib", root=True, depends_on=["npm:body@1.0.0", "npm:qs@6.7.0", "npm:mocha@5.0.0"]),
        comp("npm:body@1.0.0", "body", depends_on=["npm:qs@6.7.0"], direct=True),
        comp("npm:qs@6.7.0", "qs", direct=True),
        comp("npm:mocha@5.0.0", "mocha", scope="dev", depends_on=["npm:minimist@0.0.8"], direct=True),
        comp("npm:minimist@0.0.8", "minimist", scope="dev"),
        comp("npm:unused@2.0.0", "unused"),
    ]
    data["components"][0]["depends_on"].append("npm:unused@2.0.0")
    return data


def advisory(aid, component_id, text="", withdrawn=None):
    return {"id": aid, "summary": text, "details": "", "withdrawn": withdrawn,
            "affected": [{"component_id": component_id, "fixed": ["9.9.9"]}]}


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = pathlib.Path(self.tmp.name)
        for rel, content in FILES.items():
            (self.project / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.project / rel).write_text(content)

    def run_check(self, *advisories):
        result = check.check(inventory_data(), {"advisories": list(advisories)}, self.project)
        return {(r["advisory_id"], r["component_id"]): r for r in result["results"]}, result

    def test_shipped_files_follow_package_json(self):
        _, result = self.run_check()
        self.assertEqual(result["code_files_scanned"], 4)
        self.assertEqual(result["shipped_code_files"], 2)

    def test_runtime_package_with_shipped_import_is_conditional(self):
        r, _ = self.run_check(advisory("CVE-1", "npm:qs@6.7.0"))
        res = r[("CVE-1", "npm:qs@6.7.0")]
        self.assertEqual(res["proposed_reachability"], "conditional")
        self.assertEqual([(h["file"], h["line"]) for h in res["call_sites"]], [("lib/app.js", 1)])

    def test_dev_only_is_not_reachable(self):
        r, _ = self.run_check(advisory("CVE-2", "npm:minimist@0.0.8"))
        res = r[("CVE-2", "npm:minimist@0.0.8")]
        self.assertEqual((res["proposed_reachability"], res["confidence"]), ("not-reachable", "high"))
        self.assertIn("required or imported in test/app.test.js", " ".join(res["evidence"]))

    def test_unimported_runtime_package_is_not_reachable(self):
        r, _ = self.run_check(advisory("CVE-3", "npm:unused@2.0.0"))
        self.assertEqual(r[("CVE-3", "npm:unused@2.0.0")]["proposed_reachability"], "not-reachable")

    def test_function_tokens_are_precise(self):
        text = "Calling `qs.stringify()` crashes; `qs.parse` with `JSON.parse`; see `poc.js` and `response.redirect()`"
        self.assertEqual(check.function_tokens(text), ["qs.parse", "qs.stringify", "response.redirect"])
        r, _ = self.run_check(advisory("CVE-4", "npm:qs@6.7.0", text))
        evidence = " ".join(r[("CVE-4", "npm:qs@6.7.0")]["evidence"])
        self.assertIn("`qs.stringify`; no call or definition", evidence)  # comment and JSON.stringify ignored
        self.assertIn("`qs.parse`; found in shipped code at lib/app.js:4", evidence)
        self.assertIn("`response.redirect`; found in shipped code at lib/app.js:5", evidence)

    def test_withdrawn_advisory(self):
        r, _ = self.run_check(advisory("CVE-5", "npm:qs@6.7.0", withdrawn="2025-12-02T00:00:00Z"))
        self.assertEqual(r[("CVE-5", "npm:qs@6.7.0")]["proposed_reachability"], "not-reachable")

    def test_root_advisory_is_conditional(self):
        r, _ = self.run_check(advisory("CVE-6", "npm:lib@1.0.0"))
        self.assertEqual(r[("CVE-6", "npm:lib@1.0.0")]["proposed_reachability"], "conditional")

    def test_direct_ancestors(self):
        paths = check.direct_ancestors(inventory_data(), "npm:qs@6.7.0")
        self.assertEqual(paths["npm:body@1.0.0"], ["npm:lib@1.0.0", "npm:body@1.0.0", "npm:qs@6.7.0"])
        self.assertEqual(paths["npm:qs@6.7.0"], ["npm:lib@1.0.0", "npm:qs@6.7.0"])

    def test_import_pattern(self):
        p = check.import_pattern("qs")
        for line in ["require('qs')", 'import x from "qs"', "import('qs/lib/x')", "import 'qs'"]:
            self.assertTrue(p.search(line), line)
        self.assertFalse(p.search("require('qsx')"))


if __name__ == "__main__":
    unittest.main()
