import importlib.util
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "secdepth" / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("match", SCRIPTS / "match.py")
match = importlib.util.module_from_spec(spec)
spec.loader.exec_module(match)
import inventory  # noqa: E402


def comp(cid, name, version, ecosystem="npm", root=False):
    return {"id": cid, "name": name, "ecosystem": ecosystem, "version": version, "scope": "runtime", "root": root,
            "depends_on": [], "evidence": [{"identifier": "t", "location": "t", "confidence": "exact"}]}


def inv(*components):
    data = inventory.new_inventory("t", "0", "source", ".", "npm:app@1.0.0")
    data["components"] = [comp("npm:app@1.0.0", "app", "1.0.0", root=True)] + list(components)
    return data


RECORDS = {
    "GHSA-aaaa": {"id": "GHSA-aaaa", "aliases": ["CVE-2022-0001"], "summary": "qs pollution", "modified": "m1",
                  "published": "2022-01-01T00:00:00Z",
                  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                  "database_specific": {"cwe_ids": ["CWE-1321"], "severity": "HIGH"},
                  "affected": [{"package": {"name": "qs", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [
                      {"introduced": "6.7.0"}, {"fixed": "6.7.3"}, {"introduced": "6.9.0"}, {"fixed": "6.9.7"}]}]}],
                  "references": [{"url": "https://example.test/advisory"}]},
    "PYSEC-1": {"id": "PYSEC-1", "aliases": ["CVE-2022-0001"], "modified": "m1", "affected": []},
    "GHSA-bbbb": {"id": "GHSA-bbbb", "summary": "no cve", "modified": "m2", "database_specific": {"severity": "MODERATE"},
                  "affected": [{"package": {"name": "qs", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [
                      {"introduced": "0"}, {"fixed": "6.14.1"}]}]}]},
}


class FakeFetch:
    def __init__(self, hits, pages=False):
        self.hits, self.pages, self.calls = hits, pages, []

    def __call__(self, url, payload=None):
        self.calls.append(url)
        if url == match.OSV_BATCH:
            results = []
            for q in payload["queries"]:
                found = [{"id": i, "modified": RECORDS[i]["modified"]} for i in self.hits.get(q["package"]["name"], [])]
                if self.pages and "page_token" not in q and len(found) > 1:
                    results.append({"vulns": found[:1], "next_page_token": "p2"})
                elif self.pages and "page_token" in q:
                    results.append({"vulns": found[1:]})
                else:
                    results.append({"vulns": found})
            return {"results": results}
        if url.startswith(match.OSV_VULN):
            return RECORDS[url[len(match.OSV_VULN):]]
        raise AssertionError("unexpected fetch " + url)


class CvssTests(unittest.TestCase):
    def test_known_scores(self):
        self.assertEqual(match.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(match.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), 7.5)
        self.assertEqual(match.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(match.cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"), 5.0)
        self.assertEqual(match.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)

    def test_unparseable_vectors(self):
        self.assertIsNone(match.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
        self.assertIsNone(match.cvss3_score("CVSS:3.1/AV:X"))
        self.assertEqual(match.severity_label(9.8), "critical")
        self.assertEqual(match.severity_label(4.0), "medium")


class VersionTests(unittest.TestCase):
    def test_ordering(self):
        k = match.version_key
        self.assertLess(k("1.2.3"), k("1.10.0"))
        self.assertLess(k("1.0.0-beta.1"), k("1.0.0"))
        self.assertEqual(k("v2.0"), k("2.0.0"))

    def test_fixed_version_on_matching_line(self):
        aff = RECORDS["GHSA-aaaa"]["affected"][0]
        self.assertEqual(match.fixed_versions_for(aff, "6.7.0"), ["6.7.3"])
        self.assertEqual(match.fixed_versions_for(aff, "6.9.1"), ["6.9.7"])
        self.assertEqual(match.ranges_text(aff), [">=6.7.0 <6.7.3 >=6.9.0 <6.9.7"])


class MatchTests(unittest.TestCase):
    def run_match(self, data, fetch, **kw):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return match.match_inventory(data, match.Matcher(fetch=fetch, cache_dir=tmp.name, **kw), enrich=False), tmp.name

    def test_aliases_merge_into_one_advisory(self):
        result, _ = self.run_match(inv(comp("npm:qs@6.7.0", "qs", "6.7.0")),
                                   FakeFetch({"qs": ["GHSA-aaaa", "PYSEC-1", "GHSA-bbbb"]}))
        ids = [a["id"] for a in result["advisories"]]
        self.assertEqual(ids, ["CVE-2022-0001", "GHSA-bbbb"])
        first = result["advisories"][0]
        self.assertEqual(first["aliases"], ["GHSA-aaaa", "PYSEC-1"])
        self.assertEqual(first["severity"], {"score": 7.5, "vector": RECORDS["GHSA-aaaa"]["severity"][0]["score"],
                                             "label": "high", "cwe": "CWE-1321"})
        self.assertEqual(first["affected"][0]["fixed"], ["6.7.3"])
        self.assertEqual(result["advisories"][1]["severity"]["label"], "medium")

    def test_unknown_versions_and_native_are_not_queried(self):
        native = comp("native:openssl@unknown", "openssl", None, ecosystem="native")
        native["version_range"] = ">=1.1.1a <=1.1.1k"
        fetch = FakeFetch({})
        result, _ = self.run_match(inv(native, comp("generic:zlib@1.2.11", "zlib", "1.2.11", ecosystem="generic")), fetch)
        reasons = {u["component_id"]: u["reason"] for u in result["unqueried"]}
        self.assertIn("candidate range >=1.1.1a <=1.1.1k", reasons["native:openssl@unknown"])
        self.assertIn("no OSV ecosystem", reasons["generic:zlib@1.2.11"])
        self.assertEqual(result["advisories"], [])

    def test_pagination(self):
        fetch = FakeFetch({"qs": ["GHSA-aaaa", "GHSA-bbbb"]}, pages=True)
        result, _ = self.run_match(inv(comp("npm:qs@6.7.0", "qs", "6.7.0")), fetch)
        self.assertEqual(len(result["advisories"]), 2)
        self.assertEqual(fetch.calls.count(match.OSV_BATCH), 2)

    def test_offline_uses_cache_only(self):
        data = inv(comp("npm:qs@6.7.0", "qs", "6.7.0"))
        online, cache = self.run_match(data, FakeFetch({"qs": ["GHSA-aaaa"]}))

        def no_network(url, payload=None):
            raise AssertionError("network used offline")

        offline = match.match_inventory(data, match.Matcher(fetch=no_network, cache_dir=cache, offline=True), enrich=False)
        self.assertEqual([a["id"] for a in offline["advisories"]], [a["id"] for a in online["advisories"]])

    def test_multiple_cves_in_one_group_are_flagged(self):
        RECORDS["GHSA-cccc"] = {"id": "GHSA-cccc", "aliases": ["CVE-2024-1", "CVE-2026-2"], "modified": "m3", "affected": []}
        self.addCleanup(RECORDS.pop, "GHSA-cccc")
        result, _ = self.run_match(inv(comp("npm:qs@6.7.0", "qs", "6.7.0")), FakeFetch({"qs": ["GHSA-cccc"]}))
        self.assertIn("CVE-2024-1, CVE-2026-2", result["advisories"][0]["notes"][0])


if __name__ == "__main__":
    unittest.main()
