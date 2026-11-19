"""End to end without network: resolve -> match (fake OSV) -> check -> draft -> render."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secdepth" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import check  # noqa: E402
import draft  # noqa: E402
import inventory  # noqa: E402
import match  # noqa: E402
import render_report  # noqa: E402
import resolve  # noqa: E402

LOCK = {"name": "svc", "version": "1.0.0", "lockfileVersion": 3, "packages": {
    "": {"name": "svc", "version": "1.0.0", "dependencies": {"qs": "6.7.0"}, "devDependencies": {"mocha": "5.0.0"}},
    "node_modules/qs": {"version": "6.7.0"},
    "node_modules/mocha": {"version": "5.0.0", "dev": True, "dependencies": {"minimist": "0.0.8"}},
    "node_modules/minimist": {"version": "0.0.8", "dev": True}}}
RECORDS = {
    "GHSA-qs": {"id": "GHSA-qs", "aliases": ["CVE-2022-24999"], "modified": "m", "summary": "qs prototype pollution",
                "details": "Crafted query strings reach `qs.parse` and hang the process.",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                "affected": [{"package": {"name": "qs", "ecosystem": "npm"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.7.0"}, {"fixed": "6.7.3"}]}]}]},
    "GHSA-mm": {"id": "GHSA-mm", "aliases": ["CVE-2021-44906"], "modified": "m", "summary": "minimist prototype pollution",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"package": {"name": "minimist", "ecosystem": "npm"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.4"}]}]}]},
}
HITS = {"qs": ["GHSA-qs"], "minimist": ["GHSA-mm"]}


def fake_fetch(url, payload=None, headers=None):
    if url == match.OSV_BATCH:
        return {"results": [{"vulns": [{"id": i, "modified": "m"} for i in HITS.get(q["package"]["name"], [])]}
                            for q in payload["queries"]]}
    return RECORDS[url[len(match.OSV_VULN):]]


class PipelineTests(unittest.TestCase):
    def test_source_project_end_to_end(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        project = pathlib.Path(tmp.name) / "svc"
        (project / "lib").mkdir(parents=True)
        (project / "package.json").write_text(json.dumps({"name": "svc", "version": "1.0.0", "files": ["lib/"]}))
        (project / "package-lock.json").write_text(json.dumps(LOCK))
        (project / "lib" / "index.js").write_text("const qs = require('qs');\nmodule.exports = s => qs.parse(s);\n")
        out = project / "security-findings"
        out.mkdir()

        data = resolve.resolve_project(project, generate=False)
        self.assertEqual(inventory.validate(data), [])
        matcher = match.Matcher(fetch=fake_fetch, cache_dir=str(pathlib.Path(tmp.name) / "cache"))
        matches = match.match_inventory(data, matcher, enrich=False)
        checks = check.check(data, matches, project)
        report = draft.build(data, matches, checks)
        self.assertEqual(render_report.validate(report), [])
        (out / "draft.json").write_text(json.dumps(report))
        proc = subprocess.run([sys.executable, "-I", str(SCRIPTS / "render_report.py"), str(out / "draft.json"),
                               "--output-dir", str(out)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

        rendered = json.loads((out / "report.json").read_text())
        findings = {f["id"]: f for f in rendered["vulnerabilities"]}
        qs = findings["CVE-2022-24999"]
        self.assertEqual((qs["applicability"], qs["exploitability"]["reachability"], qs["feasibility"]),
                         ("affected", "conditional", "feasible"))
        self.assertIn("qs.parse", " ".join(qs["exploitability"]["evidence"]))
        mm = findings["CVE-2021-44906"]
        self.assertEqual((mm["applicability"], mm["exploitability"]["reachability"]), ("not-affected", "not-reachable"))
        self.assertEqual(rendered["report"]["finding_groups"],
                         {"No deployable fix": 0, "Fix available": 1, "No confirmed local exposure / assessment incomplete": 1})
        self.assertTrue((out / "report.html").read_text().startswith("<!doctype html>"))


if __name__ == "__main__":
    unittest.main()
