import copy
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "skills" / "secdepth" / "scripts" / "inventory.py"
SCHEMA = ROOT / "skills" / "secdepth" / "references" / "inventory-schema.json"

spec = importlib.util.spec_from_file_location("inventory", SCRIPT)
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)


def valid():
    data = inv.new_inventory("test", "0", "source", ".", "npm:app@1.0.0")
    data["components"] = [
        {"id": "npm:app@1.0.0", "name": "app", "ecosystem": "npm", "version": "1.0.0", "scope": "runtime",
         "root": True, "depends_on": ["npm:qs@6.7.0"],
         "evidence": [{"identifier": "package.json", "location": "package.json", "confidence": "exact"}]},
        {"id": "npm:qs@6.7.0", "name": "qs", "ecosystem": "npm", "version": "6.7.0", "scope": "runtime",
         "direct": True, "evidence": [{"identifier": "npm-lockfile", "location": "package-lock.json", "confidence": "exact"}]},
    ]
    return data


class ValidateTests(unittest.TestCase):
    def test_valid_inventory(self):
        self.assertEqual(inv.validate(valid()), [])

    def test_unknown_version_is_allowed(self):
        data = valid()
        data["components"][1]["version"] = None
        data["components"][1]["version_range"] = ">=6.0.0 <7.0.0"
        self.assertEqual(inv.validate(data), [])

    def test_component_needs_evidence(self):
        data = valid()
        data["components"][1]["evidence"] = []
        self.assertTrue(any("evidence" in e for e in inv.validate(data)))

    def test_bad_enums_and_references(self):
        data = valid()
        data["components"][1]["scope"] = "test"
        data["components"][1]["evidence"][0]["confidence"] = "certain"
        data["components"][0]["depends_on"] = ["npm:missing@1"]
        data["root_component_id"] = "npm:nope@1"
        problems = " ".join(inv.validate(data))
        for needle in ("scope", "confidence", "unknown component", "root_component_id"):
            self.assertIn(needle, problems)

    def test_duplicate_ids(self):
        data = valid()
        data["components"].append(copy.deepcopy(data["components"][1]))
        self.assertTrue(any("duplicate" in e for e in inv.validate(data)))

    def test_complete_coverage_cannot_hide_failures(self):
        data = valid()
        data["coverage"]["entries"] = [{"path": "fw.bin", "status": "unpack-failed", "reason": "encrypted"}]
        self.assertTrue(any("coverage.complete" in e for e in inv.validate(data)))
        data["coverage"]["complete"] = False
        self.assertEqual(inv.validate(data), [])

    def test_wrong_schema_and_top_level(self):
        self.assertEqual(inv.validate([]), ["top level: expected an object"])
        data = valid()
        data["schema_version"] = "2.0"
        self.assertTrue(any("schema_version" in e for e in inv.validate(data)))

    def test_schema_file_matches_constants(self):
        schema = json.loads(SCHEMA.read_text())
        self.assertEqual(schema["properties"]["schema_version"]["const"], inv.SCHEMA_VERSION)
        self.assertEqual(set(schema["$defs"]["component"]["properties"]["scope"]["enum"]), inv.SCOPES)
        self.assertEqual(set(schema["$defs"]["evidence"]["properties"]["confidence"]["enum"]), inv.CONFIDENCE)
        statuses = schema["$defs"]["coverage"]["properties"]["entries"]["items"]["properties"]["status"]["enum"]
        self.assertEqual(set(statuses), inv.COVERAGE_STATUS)

    def test_component_id(self):
        self.assertEqual(inv.component_id("npm", "qs", "6.7.0"), "npm:qs@6.7.0")
        self.assertEqual(inv.component_id("native", "openssl", None), "native:openssl@unknown")


if __name__ == "__main__":
    unittest.main()
