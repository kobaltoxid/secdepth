import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secdepth" / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("draft", SCRIPTS / "draft.py")
draft = importlib.util.module_from_spec(spec)
spec.loader.exec_module(draft)
import inventory  # noqa: E402
import render_report  # noqa: E402


def comp(cid, scope="runtime", depends_on=(), root=False):
    name = cid.split(":", 1)[1].rsplit("@", 1)[0]
    return {"id": cid, "name": name, "ecosystem": "npm", "version": cid.rsplit("@", 1)[1], "scope": scope, "root": root,
            "depends_on": list(depends_on), "evidence": [{"identifier": "t", "location": "t", "confidence": "exact"}]}


def data():
    inv = inventory.new_inventory("t", "0", "source", ".", "npm:app@1.0.0")
    inv["components"] = [comp("npm:app@1.0.0", root=True, depends_on=["npm:qs@6.7.0", "npm:hbs@4.0.0"]),
                         comp("npm:qs@6.7.0"),
                         comp("npm:hbs@4.0.0", scope="dev", depends_on=["npm:handlebars@4.0.0"]),
                         comp("npm:handlebars@4.0.0", scope="dev")]
    return inv


def adv(aid, component_id, fixed, **extra):
    a = {"id": aid, "aliases": ["GHSA-x"], "summary": "summary " + aid, "details": "details " + aid, "withdrawn": None,
         "severity": {"score": 7.5, "vector": "CVSS:3.1/AV:N", "label": "high", "cwe": "CWE-1321"},
         "references": ["https://example.test/ref"], "osv_urls": ["https://osv.dev/vulnerability/GHSA-x"],
         "affected": [{"component_id": component_id, "fixed": fixed, "ranges": [">=1 <2"]}], "kev": None, "epss": None,
         "notes": []}
    a.update(extra)
    return a


def result(aid, cid, scope, verdict, fix=None):
    return {"advisory_id": aid, "component_id": cid, "scope": scope, "proposed_reachability": verdict,
            "confidence": "medium", "evidence": ["evidence for " + cid], "call_sites": [], "fix_check": fix}


FIX = {"upgrade": "app@^1.0.0", "upgrade_resolved": {"app": ["1.4.0"]}, "resolved_versions": ["6.16.2"],
       "advisory_cleared": True, "checked_at": "2026-11-19T00:00:00Z"}


class DraftTests(unittest.TestCase):
    def build(self, advisories, results):
        return draft.build(data(), {"advisories": advisories, "generated_at": "2026-11-19T00:00:00Z"},
                           {"results": results, "shipped_files_rule": "rule"})

    def test_runtime_finding_uses_verified_upgrade(self):
        report = self.build([adv("CVE-1", "npm:qs@6.7.0", ["6.7.3"], kev={"date_added": "2024-01-01"})],
                            [result("CVE-1", "npm:qs@6.7.0", "runtime", "conditional", FIX)])
        f = report["vulnerabilities"][0]
        self.assertEqual((f["applicability"], f["feasibility"], f["update_status"]), ("affected", "feasible", "released"))
        self.assertEqual(f["recommended_target_version"], "app 1.4.0 (resolves qs 6.16.2)")
        self.assertIn("CISA Known Exploited", f["description"])
        self.assertTrue(f["review"]["needed"])
        self.assertEqual(render_report.validate(report), [])

    def test_dev_only_finding_is_not_affected(self):
        report = self.build([adv("CVE-2", "npm:handlebars@4.0.0", ["4.3.0"])],
                            [result("CVE-2", "npm:handlebars@4.0.0", "dev", "not-reachable", FIX)])
        f = report["vulnerabilities"][0]
        self.assertEqual(f["applicability"], "not-affected")
        self.assertEqual(f["recommended_target_version"], "handlebars 4.3.0")
        self.assertIn("development dependency hbs", f["recommendation"])
        self.assertFalse(f["review"]["needed"])

    def test_unverified_fix_and_no_fix(self):
        report = self.build([adv("CVE-3", "npm:qs@6.7.0", ["6.7.3"]), adv("CVE-4", "npm:qs@6.7.0", [])],
                            [result("CVE-3", "npm:qs@6.7.0", "runtime", "conditional"),
                             result("CVE-4", "npm:qs@6.7.0", "runtime", "not-reachable")])
        f3, f4 = report["vulnerabilities"]
        self.assertEqual((f3["feasibility"], f3["recommended_target_version"]), ("unknown", "qs 6.7.3"))
        self.assertIn("not verified", f3["recommendation"])
        self.assertEqual((f4["update_status"], f4["recommended_target_version"]), ("unknown", "unknown"))

    def test_withdrawn_and_notes(self):
        report = self.build([adv("CVE-5", "npm:qs@6.7.0", [], withdrawn="2025-12-02T00:00:00Z",
                                 notes=["Source records list CVE-5, CVE-6 as aliases"])],
                            [result("CVE-5", "npm:qs@6.7.0", "runtime", "not-reachable")])
        f = report["vulnerabilities"][0]
        self.assertEqual(f["applicability"], "not-affected")
        self.assertIn("withdrawn", f["recommendation"])
        self.assertTrue(f["review"]["needed"])
        self.assertIn("aliases", f["description"])

    def test_report_target_and_sources(self):
        report = self.build([adv("CVE-1", "npm:qs@6.7.0", ["6.7.3"])],
                            [result("CVE-1", "npm:qs@6.7.0", "runtime", "conditional")])
        self.assertEqual(report["report"]["target"]["mode"], "project-scan")
        self.assertEqual({s["id"] for s in report["sources"]}, {"osv-ghsa-x", "cve-1-ref1"})
        self.assertEqual(report["report"]["title"], "Project scan: app 1.0.0")


if __name__ == "__main__":
    unittest.main()
