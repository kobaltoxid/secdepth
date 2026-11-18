import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "secdepth" / "scripts" / "render_report.py"

spec = importlib.util.spec_from_file_location("render_report", SCRIPT)
rr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rr)


def finding(fid, **overrides):
    f = {
        "id": fid,
        "description": "desc " + fid,
        "applicability": "affected",
        "affected_component_ids": ["lib"],
        "exploitability": {"presence": "present", "reachability": "reachable", "confidence": "high"},
        "update_status": "no-fix",
        "feasibility": "unknown",
        "sources": ["s1"],
    }
    f.update(overrides)
    return f


def report(*findings):
    return {
        "report": {"title": "Test", "generated_at": "2026-11-18T00:00:00Z", "root_component_id": "app"},
        "components": [
            {"id": "app", "name": "app", "version": "1.0"},
            {"id": "lib", "name": "lib", "version": "2.0"},
        ],
        "sources": [
            {"id": "s1", "url": "https://nvd.nist.gov/vuln/detail/CVE-0", "publisher": "NVD",
             "type": "primary", "accessed_at": "2026-11-18", "supports": "range"},
        ],
        "vulnerabilities": list(findings),
    }


def fixable(fid, **overrides):
    base = dict(update_status="released", recommended_target_version="2.1", feasibility="feasible")
    base.update(overrides)
    return finding(fid, **base)


def ids(data):
    return [f["id"] for f in rr.normalize(data)["vulnerabilities"]]


class GroupTests(unittest.TestCase):
    def test_deployable_fix_requires_every_condition(self):
        self.assertEqual(rr.group(fixable("A")), "Fix available")
        for broken in (
            {"update_status": "planned"},
            {"recommended_target_version": ""},
            {"recommended_target_version": "unknown"},
            {"recommended_target_version": "undetermined"},
            {"recommended_target_version": None},
            {"feasibility": "blocked"},
        ):
            with self.subTest(broken=broken):
                self.assertEqual(rr.group(fixable("A", **broken)), "No deployable fix")

    def test_unassessed_or_not_affected_goes_last(self):
        for value in ("not-affected", "unknown", "undetermined", None):
            with self.subTest(value=value):
                self.assertEqual(rr.group(finding("A", applicability=value)), rr.GROUPS[2])
        missing = finding("A")
        del missing["applicability"]
        self.assertEqual(rr.group(missing), rr.GROUPS[2])

    def test_nested_update_fallback(self):
        f = finding("A", update={"status": "released", "recommended_target_version": "2.1", "feasibility": "feasible"})
        del f["update_status"], f["feasibility"]
        self.assertEqual(rr.group(f), "Fix available")

    def test_group_order_and_counts(self):
        data = rr.normalize(report(finding("C", applicability="unknown"), fixable("B"), finding("A")))
        self.assertEqual([f["id"] for f in data["vulnerabilities"]], ["A", "B", "C"])
        self.assertEqual(data["report"]["finding_groups"], {name: 1 for name in rr.GROUPS})
        self.assertIn("ordering_policy", data["report"])


class OrderTests(unittest.TestCase):
    def test_sla_rank_first_ascending(self):
        data = report(
            finding("CVE-1", cvss={"score": 10.0}),
            finding("CVE-2", sla={"priority_rank": 2}),
            finding("CVE-3", sla={"priority_rank": 1}),
        )
        self.assertEqual(ids(data), ["CVE-3", "CVE-2", "CVE-1"])

    def test_string_rank_mixed_with_int(self):
        data = report(finding("CVE-1", sla={"priority_rank": "2"}), finding("CVE-2", sla={"priority_rank": 1}))
        self.assertEqual(ids(data), ["CVE-2", "CVE-1"])

    def test_non_numeric_rank_is_unranked(self):
        data = report(finding("CVE-1", sla={"priority_rank": "urgent"}), finding("CVE-2", sla={"priority_rank": 5}))
        self.assertEqual(ids(data), ["CVE-2", "CVE-1"])

    def test_score_descending_then_unscored(self):
        data = report(
            finding("CVE-1", cvss={"severity": "critical"}),
            finding("CVE-2", cvss={"score": 5.0}),
            finding("CVE-3", cvss={"score": "9.8"}),
        )
        self.assertEqual(ids(data), ["CVE-3", "CVE-2", "CVE-1"])

    def test_zero_score_is_scored(self):
        data = report(finding("CVE-1", cvss={"severity": "critical"}), finding("CVE-2", cvss={"score": 0}))
        self.assertEqual(ids(data), ["CVE-2", "CVE-1"])

    def test_equal_scores_tie_break_by_severity_then_id(self):
        data = report(
            finding("CVE-3", cvss={"score": 7.5, "severity": "medium"}),
            finding("CVE-2", cvss={"score": 7.5, "severity": "high"}),
            finding("CVE-1", cvss={"score": 7.5, "severity": "medium"}),
        )
        self.assertEqual(ids(data), ["CVE-2", "CVE-1", "CVE-3"])

    def test_unscored_by_severity_label_then_id(self):
        data = report(
            finding("CVE-3", cvss={"severity": "LOW"}),
            finding("CVE-2"),
            finding("CVE-1", cvss={"severity": "High"}),
            finding("CVE-0", cvss={"severity": "low"}),
        )
        self.assertEqual(ids(data), ["CVE-1", "CVE-0", "CVE-3", "CVE-2"])


class HtmlTests(unittest.TestCase):
    def test_escapes_untrusted_text(self):
        evil = "<script>alert(1)</script>"
        page = rr.render(rr.normalize(report(finding(evil, description=evil))))
        self.assertNotIn(evil, page)
        self.assertIn("&lt;script&gt;", page)

    def test_only_http_links(self):
        data = report(finding("A", sources=["s1", "s2", "s3"]))
        data["sources"] += [
            {"id": "s2", "url": "javascript:alert(1)", "publisher": "Bad"},
            {"id": "s3", "url": "http://example.com/a?x=1&y=2", "publisher": "Ok"},
        ]
        page = rr.render(rr.normalize(data))
        self.assertIn('href="https://nvd.nist.gov/vuln/detail/CVE-0"', page)
        self.assertIn('href="http://example.com/a?x=1&amp;y=2"', page)
        self.assertNotIn('href="javascript:', page)
        self.assertIn("Bad [s2] (invalid URL)", page)

    def test_missing_records_are_marked(self):
        data = report(finding("A", sources=["nope"], dependency_paths=[["app", "ghost"]]))
        page = rr.render(rr.normalize(data))
        self.assertIn("nope (missing source record)", page)
        self.assertIn("app @ 1.0 &rarr; ghost (missing component)", page)

    def test_dependency_path_and_claims(self):
        data = report(finding("A", dependency_paths=[["app", "lib"]],
                              claims=[{"claim": "fixed in 2.1", "source_ids": ["s1"]}]))
        page = rr.render(rr.normalize(data))
        self.assertIn("app @ 1.0 &rarr; lib @ 2.0", page)
        self.assertIn("<strong>fixed in 2.1</strong>", page)

    def test_no_external_resources(self):
        page = rr.render(rr.normalize(report(finding("A"))))
        for marker in ("<script src", "<link ", "@import"):
            self.assertNotIn(marker, page)


class ValidateTests(unittest.TestCase):
    def test_valid_report_has_no_errors(self):
        data = report(fixable("A", cvss={"score": 9.8}, sla={"priority_rank": "1"}, dependency_paths=[["app", "lib"]],
                              claims=[{"claim": "c", "source_ids": ["s1"]}], patch_eta={"certainty": "unknown", "source_ids": []}))
        self.assertEqual(rr.validate(data), [])

    def test_missing_optional_fields_are_allowed(self):
        self.assertEqual(rr.validate({"vulnerabilities": [{"id": "A"}]}), [])

    def test_reports_shape_errors(self):
        cases = {
            "cvss": ("9.8", "vulnerabilities[0].cvss: expected dict"),
            "sla": ("P1", "vulnerabilities[0].sla: expected dict"),
            "patch_eta": ("Q1", "vulnerabilities[0].patch_eta: expected dict"),
            "sources": ("s1", "vulnerabilities[0].sources: expected list"),
            "affected_component_ids": ([1], "vulnerabilities[0].affected_component_ids[0]: expected str"),
            "dependency_paths": (["app", "lib"], "vulnerabilities[0].dependency_paths[0]: expected list"),
            "claims": (["x"], "vulnerabilities[0].claims[0]: expected dict"),
            "applicability": ("Affected", "vulnerabilities[0].applicability: 'Affected' is not one of"),
            "update_status": ("fixed", "vulnerabilities[0].update_status: 'fixed' is not one of"),
            "feasibility": (True, "vulnerabilities[0].feasibility: True is not one of"),
            "id": (["A"], "vulnerabilities[0].id: expected a string"),
            "recommended_target_version": (["2.1"], "vulnerabilities[0].recommended_target_version: expected a string"),
            "sla": ({"source_id": ["s1"]}, "vulnerabilities[0].sla.source_id: expected a string"),
        }
        for field, (value, message) in cases.items():
            with self.subTest(field=field):
                errors = rr.validate(report(finding("A", **{field: value})))
                self.assertTrue(any(e.startswith(message) for e in errors), errors)

    def test_unhashable_enum_value(self):
        errors = rr.validate(report(finding("A", applicability=["affected"])))
        self.assertTrue(errors[0].startswith("vulnerabilities[0].applicability: ['affected'] is not one of"), errors)

    def test_reports_top_level_and_record_errors(self):
        self.assertEqual(rr.validate([]), ["top level: expected an object"])
        self.assertEqual(rr.validate({"vulnerabilities": 1}), ["vulnerabilities: expected list, got int"])
        errors = rr.validate({"report": "x", "components": {}, "sources": ["s"], "vulnerabilities": None})
        self.assertEqual(errors, [
            "report: expected dict, got str",
            "components: expected list, got dict",
            "sources[0]: expected dict, got str",
        ])
        data = report(finding("A"))
        data["sources"][0]["supports"] = ["a"]
        self.assertEqual(rr.validate(data), ["sources[0].supports: expected a string"])

    def test_explicit_nulls_render(self):
        for data in (
            {"report": None, "components": None, "sources": None, "vulnerabilities": None},
            report(finding("A", affected_component_ids=None, sources=None, claims=[{"claim": "c", "source_ids": None}])),
        ):
            with self.subTest(data=data):
                self.assertEqual(rr.validate(data), [])
                rr.render(rr.normalize(data))

    def test_root_component_id_must_be_string(self):
        data = report()
        data["report"]["root_component_id"] = ["app"]
        self.assertEqual(rr.validate(data), ["report.root_component_id: expected a string"])

    def test_numeric_names_render(self):
        data = report(finding("A", dependency_paths=[["app", "n"]]))
        data["components"].append({"id": "n", "name": 7, "version": 1})
        data["sources"][0]["supports"] = 3
        self.assertEqual(rr.validate(data), [])
        page = rr.render(rr.normalize(data))
        self.assertIn("app @ 1.0 &rarr; 7 @ 1", page)


class CliTests(unittest.TestCase):
    def run_cli(self, cwd, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=cwd,
                              capture_output=True, text=True, check=True)

    def test_default_output_dir_is_cwd_security_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "draft.json").write_text(json.dumps(report(finding("A"))), encoding="utf-8")
            self.run_cli(tmp, "draft.json")
            out = tmp / "security-findings"
            self.assertEqual(json.loads((out / "report.json").read_text())["vulnerabilities"][0]["id"], "A")
            self.assertTrue((out / "report.html").read_text().startswith("<!doctype html>"))

    def test_output_dir_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "draft.json").write_text(json.dumps(report(finding("A"))), encoding="utf-8")
            result = self.run_cli(tmp, "draft.json", "--output-dir", "audit/out")
            self.assertTrue((tmp / "audit/out/report.json").is_file())
            self.assertTrue((tmp / "audit/out/report.html").is_file())
            self.assertIn("report.html", result.stdout)

    def test_invalid_draft_exits_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "draft.json").write_text(json.dumps(report(finding("A", cvss="9.8", applicability="yes"))), encoding="utf-8")
            result = subprocess.run([sys.executable, str(SCRIPT), "draft.json"], cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("invalid report draft", result.stderr)
            self.assertIn("vulnerabilities[0].cvss", result.stderr)
            self.assertIn("vulnerabilities[0].applicability", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertFalse((tmp / "security-findings").exists())

    def test_rerender_is_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp)
            (tmp / "draft.json").write_text(json.dumps(report(finding("B"), fixable("A"))), encoding="utf-8")
            self.run_cli(tmp, "draft.json")
            first = (tmp / "security-findings/report.json").read_text()
            self.run_cli(tmp, "security-findings/report.json")
            self.assertEqual(first, (tmp / "security-findings/report.json").read_text())


if __name__ == "__main__":
    unittest.main()
