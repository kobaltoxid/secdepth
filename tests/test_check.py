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


class ArtifactCheckTests(unittest.TestCase):
    def test_artifact_inventory_needs_no_source(self):
        data = inventory.new_inventory("t", "0", "artifact", "app.tar", "artifact:app.tar@unknown")
        data["components"] = [comp("artifact:app.tar@unknown", "app.tar", root=True, depends_on=["npm:qs@6.7.0"]),
                              comp("npm:qs@6.7.0", "qs")]
        data["components"][1]["evidence"] = [{"identifier": "npm-package-json", "location": "app.tar!/node_modules/qs/package.json",
                                              "confidence": "exact"}]
        result = check.check(data, {"advisories": [advisory("CVE-9", "npm:qs@6.7.0"),
                                                   advisory("CVE-10", "npm:qs@6.7.0", withdrawn="2025-01-01T00:00:00Z")]}, None)
        by_id = {r["advisory_id"]: r for r in result["results"]}
        self.assertEqual(by_id["CVE-9"]["proposed_reachability"], "unknown")
        self.assertIn("app.tar!/node_modules/qs/package.json", by_id["CVE-9"]["evidence"][0])
        self.assertEqual(by_id["CVE-10"]["proposed_reachability"], "not-reachable")


class EcosystemPatternTests(unittest.TestCase):
    def test_import_patterns(self):
        cases = [
            ("PyPI", "pyyaml", "import yaml", "import yamlx"),
            ("PyPI", "jinja2", "from jinja2 import Template", "from jinja2x import t"),
            ("Go", "golang.org/x/net", '\t"golang.org/x/net/http2"', '"golang.org/x/network"'),
            ("crates.io", "serde-json", "use serde_json::Value;", "use serde_jsonx::V;"),
            ("NuGet", "Newtonsoft.Json", "using Newtonsoft.Json;", "using Newtonsoft.JsonX;"),
            ("Maven", "org.apache.logging.log4j:log4j-core", "import org.apache.logging.log4j.LogManager;",
             "import org.apache.logging.other.X;"),
        ]
        for eco, name, hit, miss in cases:
            p = check.import_pattern(name, eco)
            self.assertTrue(p.search(hit), (eco, hit))
            self.assertFalse(p.search(miss), (eco, miss))

    def test_conventional_shipped_files(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        shipped, reason = check.shipped_matcher(pathlib.Path(tmp.name))
        self.assertTrue(shipped(pathlib.Path("pkg/server.go")))
        self.assertFalse(shipped(pathlib.Path("pkg/server_test.go")))
        self.assertFalse(shipped(pathlib.Path("tests/test_app.py")))
        self.assertIn("treated as not shipped", reason)


class GovulncheckTests(unittest.TestCase):
    STREAM = "\n".join(json.dumps(x) for x in [
        {"config": {"scanner_name": "govulncheck"}},
        {"finding": {"osv": "GO-2022-0001", "trace": [
            {"module": "golang.org/x/net", "package": "golang.org/x/net/http2", "function": "Server.ServeConn"},
            {"module": "example.com/svc", "function": "main", "position": {"filename": "main.go", "line": 12}}]}},
        {"finding": {"osv": "GO-2022-0002", "trace": [{"module": "golang.org/x/text", "package": "golang.org/x/text/language"}]}},
    ])

    def run_gv(self, project, which=lambda _n: "/usr/bin/govulncheck", stdout=STREAM, code=3):
        class Proc:
            returncode, stderr = code, ""
        Proc.stdout = stdout
        return check.govulncheck_findings(project, runner=lambda *a, **k: Proc, which=which)

    def test_parser_and_levels(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        project = pathlib.Path(tmp.name)
        self.assertEqual(self.run_gv(project), ({}, False, None))  # not a Go module
        (project / "go.mod").write_text("module example.com/svc\n")
        findings, ran, note = self.run_gv(project)
        self.assertTrue(ran)
        self.assertEqual(findings["GO-2022-0001"][0]["level"], "symbol")
        self.assertEqual((findings["GO-2022-0001"][0]["file"], findings["GO-2022-0001"][0]["line"]), ("main.go", 12))
        self.assertEqual(findings["GO-2022-0002"][0]["level"], "package")
        self.assertIn("not installed", self.run_gv(project, which=lambda _n: None)[2])

    def test_verdicts_from_govulncheck(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        project = pathlib.Path(tmp.name)
        (project / "main.go").write_text('package main\nimport "golang.org/x/net/http2"\n')
        data = inventory.new_inventory("t", "0", "source", ".", "Go:example.com/svc@unknown")
        go = lambda cid, name: dict(comp(cid, name, direct=True), ecosystem="Go")
        data["components"] = [dict(comp("Go:example.com/svc@unknown", "example.com/svc", root=True,
                                        depends_on=["Go:golang.org/x/net@0.1.0", "Go:golang.org/x/text@0.3.0"]), ecosystem="Go"),
                              go("Go:golang.org/x/net@0.1.0", "golang.org/x/net"), go("Go:golang.org/x/text@0.3.0", "golang.org/x/text")]
        advisories = [dict(advisory("CVE-A", "Go:golang.org/x/net@0.1.0"), aliases=["GO-2022-0001"]),
                      dict(advisory("CVE-B", "Go:golang.org/x/text@0.3.0"), aliases=["GO-2022-0002"])]
        findings = {"GO-2022-0001": [{"level": "symbol", "function": "Server.ServeConn", "file": "main.go", "line": 12}],
                    "GO-2022-0002": [{"level": "package", "function": None, "file": None, "line": None}]}
        result = check.check(data, {"advisories": advisories}, project, govulncheck=lambda _p: (findings, True, None))
        by_id = {r["advisory_id"]: r for r in result["results"]}
        self.assertEqual((by_id["CVE-A"]["proposed_reachability"], by_id["CVE-A"]["confidence"]), ("reachable", "high"))
        self.assertIn("Server.ServeConn is called", " ".join(by_id["CVE-A"]["evidence"]))
        self.assertEqual(by_id["CVE-B"]["proposed_reachability"], "not-reachable")
        self.assertEqual(result["govulncheck"], "ran")


class ArtifactEvidenceTests(unittest.TestCase):
    def test_code_evidence_updates_verdict(self):
        data = inventory.new_inventory("t", "0", "artifact", "app.tar", "artifact:app.tar@unknown")
        data["components"] = [comp("artifact:app.tar@unknown", "app.tar", root=True, depends_on=["npm:qs@6.7.0"]),
                              comp("npm:qs@6.7.0", "qs")]
        code = {("CVE-9", "npm:qs@6.7.0"): {"proposed_reachability": "conditional",
                                            "facts": ["Class Parser is present at app.tar!/lib/qs.jar!/Parser.class."]}}
        result = check.check(data, {"advisories": [advisory("CVE-9", "npm:qs@6.7.0")]}, None, evidence=code)
        row = result["results"][0]
        self.assertEqual((row["proposed_reachability"], row["confidence"]), ("conditional", "medium"))
        self.assertIn("Class Parser is present", " ".join(row["evidence"]))


class EvidenceContractTests(unittest.TestCase):
    """secpeel writes evidence.json; secdepth must accept what it writes today and reject what it cannot read."""
    FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "secpeel-evidence-1.0.json"

    def load(self):
        return json.loads(self.FIXTURE.read_text())

    def test_accepts_the_producer_fixture(self):
        self.assertEqual(check.validate_evidence(self.load()), [])

    def test_accepts_extra_optional_fields_and_minor_versions(self):
        data = self.load()
        data["schema_version"] = "1.4"
        data["generator"] = {"name": "secpeel"}
        data["results"][0]["new_hint"] = "ignored"
        self.assertEqual(check.validate_evidence(data), [])

    def test_accepts_empty_results(self):
        data = self.load()
        data["results"] = []
        self.assertEqual(check.validate_evidence(data), [])

    def test_rejects_unsupported_major_version(self):
        data = self.load()
        data["schema_version"] = "2.0"
        problems = check.validate_evidence(data, "ev.json")
        self.assertTrue(any("ev.json" in p and "2.0" in p for p in problems), problems)

    def test_rejects_missing_required_fields(self):
        data = self.load()
        del data["results"]
        self.assertIn("ev.json: results must be a list", check.validate_evidence(data, "ev.json"))
        data = self.load()
        del data["results"][0]["facts"]
        self.assertTrue(any("results[0].facts" in p for p in check.validate_evidence(data)))

    def test_cli_rejects_a_bad_file(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        data = inventory.new_inventory("t", "0", "artifact", "a.tar", "artifact:a.tar@unknown")
        data["components"] = [comp("artifact:a.tar@unknown", "a.tar", root=True)]
        (root / "inv.json").write_text(json.dumps(data))
        (root / "m.json").write_text(json.dumps({"advisories": []}))
        bad = self.load()
        bad["schema_version"] = "2.0"
        (root / "ev.json").write_text(json.dumps(bad))
        self.assertEqual(check.main([str(root / "inv.json"), str(root / "m.json"), "--evidence", str(root / "ev.json")]), 1)
