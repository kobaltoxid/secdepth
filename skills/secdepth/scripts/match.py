#!/usr/bin/env python3
"""Match a secdepth inventory against published advisories, without a language model.

Usage: match.py <inventory.json> [--output FILE] [--cache-dir DIR] [--offline] [--no-enrich]

Queries OSV for every component with an exact version and an OSV ecosystem, fetches each advisory,
merges aliases (CVE, GHSA, OSV IDs) into one advisory, computes CVSS v3 base scores, and adds CISA KEV
and EPSS data. Components with an unknown version or no OSV ecosystem are listed as not queried.
"""
import argparse
import datetime
import json
import math
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import inventory  # noqa: E402
import osvdata  # noqa: E402
import versions  # noqa: E402

VERSION = "0.1.0"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = 2000
# NVD allows 5 requests per 30 s without an API key and 50 with one.
NVD_DELAY = {False: 6.5, True: 0.7}
BATCH_SIZE = 500
OSV_ECOSYSTEMS = {
    "npm", "PyPI", "Maven", "Go", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex", "Pub", "SwiftURL",
    "Debian", "Alpine", "Ubuntu", "Rocky Linux", "AlmaLinux", "Red Hat", "SUSE", "openSUSE", "Linux",
}
SEVERITY_ORDER = ["none", "low", "medium", "high", "critical"]


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def http_fetch(url, payload=None, timeout=60, headers=None):
    """Default network access; tests replace it."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=dict({"Content-Type": "application/json",
                                                               "User-Agent": "secdepth/" + VERSION}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


# --- CVSS v3 base score (FIRST CVSS v3.1 specification, section 7) ---------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value):
    scaled = int(round(value * 100000))
    return scaled / 100000.0 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Return the base score for a CVSS:3.x vector, or None if it cannot be parsed."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10))


def severity_label(score):
    if score is None:
        return None
    if score == 0:
        return "none"
    return "low" if score < 4 else "medium" if score < 7 else "high" if score < 9 else "critical"


# --- version handling ---------------------------------------------------------------------------

def version_key(version):
    """Order versions well enough for semver-like schemes; returns None when not comparable."""
    v = str(version).strip().lstrip("vV").split("+", 1)[0]
    main, _, pre = v.partition("-")
    nums = re.findall(r"\d+", main)
    if not nums:
        return None
    release = tuple(int(n) for n in nums[:4]) + (0,) * (4 - len(nums[:4]))
    return release + ((1, "") if not pre else (0, pre))


def fixed_versions_for(affected, version):
    """Fixed versions from the ranges that contain `version` (all fixed events if not comparable)."""
    key = version_key(version)
    fixed = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") == "GIT":
            continue
        introduced, events = None, rng.get("events") or []
        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            elif "fixed" in event:
                lo = version_key(introduced) if introduced not in (None, "0") else (0,)
                hi = version_key(event["fixed"])
                if key is None or lo is None or hi is None or (lo <= key < hi):
                    fixed.append(event["fixed"])
    return sorted(set(fixed), key=lambda f: version_key(f) or (0,))


def ranges_text(affected):
    out = []
    for rng in affected.get("ranges") or []:
        if rng.get("type") == "GIT":
            continue
        parts = []
        for event in rng.get("events") or []:
            for kind, value in event.items():
                parts.append({"introduced": ">=", "fixed": "<", "last_affected": "<=", "limit": "<"}.get(kind, kind) + value)
        out.append(" ".join(p for p in parts if p != ">=0") or "all versions")
    return out


# --- matching -------------------------------------------------------------------------------------

class Matcher:
    def __init__(self, fetch=http_fetch, cache_dir=None, offline=False, nvd_api_key=None, sleep=time.sleep, osv_data=None):
        self.fetch = fetch
        self.store = osvdata.Store(osv_data) if osv_data else None
        self.offline = offline or self.store is not None
        self.not_comparable = []
        self.nvd_api_key = nvd_api_key
        self.sleep = sleep
        self.cache = pathlib.Path(cache_dir) if cache_dir else None
        self.sources = []

    def _cached(self, name):
        if self.cache and (self.cache / name).is_file():
            return json.loads((self.cache / name).read_text(encoding="utf-8"))
        return None

    def _store(self, name, data):
        if self.cache:
            (self.cache / name).parent.mkdir(parents=True, exist_ok=True)
            (self.cache / name).write_text(json.dumps(data), encoding="utf-8")

    def query(self, components):
        """Return {component_id: [(osv_id, modified)]} using OSV querybatch with pagination."""
        hits = {c["id"]: [] for c in components}
        if self.store is not None:
            return self._query_store(components, hits)
        if self.offline:
            cached = self._cached("querybatch.json") or {}
            return {cid: [tuple(x) for x in cached.get(cid, [])] for cid in hits}
        for start in range(0, len(components), BATCH_SIZE):
            chunk = components[start:start + BATCH_SIZE]
            pending = [(c, None) for c in chunk]
            while pending:
                queries = []
                for comp, token in pending:
                    q = {"package": {"name": comp["name"], "ecosystem": osv_ecosystem(comp)}, "version": comp["version"]}
                    if token:
                        q["page_token"] = token
                    queries.append(q)
                results = self.fetch(OSV_BATCH, {"queries": queries}).get("results", [])
                next_pending = []
                for (comp, _), res in zip(pending, results):
                    hits[comp["id"]].extend((v["id"], v.get("modified")) for v in res.get("vulns", []))
                    if res.get("next_page_token"):
                        next_pending.append((comp, res["next_page_token"]))
                pending = next_pending
        self._store("querybatch.json", hits)
        self.sources.append({"name": "OSV querybatch", "url": OSV_BATCH, "accessed_at": now()})
        return hits

    def _query_store(self, components, hits):
        """Evaluate downloaded OSV records locally with exact per-ecosystem version comparison."""
        used = set()
        for comp in components:
            eco = osv_ecosystem(comp)
            base = eco.split(":")[0]
            if not self.store.available(base):
                self.not_comparable.append({"component_id": comp["id"], "reason": "no OSV export downloaded for %s" % base})
                continue
            used.add(base)
            for record in self.store.records_for(base, comp["name"]):
                for affected in record.get("affected") or []:
                    pkg = affected.get("package") or {}
                    same_eco = pkg.get("ecosystem") == eco or (":" not in eco and pkg.get("ecosystem", "").split(":")[0] == eco)
                    if not same_eco or osvdata.normalise(base, pkg.get("name", "")) != osvdata.normalise(base, comp["name"]):
                        continue
                    verdict = versions.affects(affected, comp["version"], eco)
                    if verdict is None:
                        self.not_comparable.append({"component_id": comp["id"], "advisory": record["id"],
                                                    "reason": "version could not be compared in %s" % eco})
                    elif verdict and (record["id"], record.get("modified")) not in hits[comp["id"]]:
                        hits[comp["id"]].append((record["id"], record.get("modified")))
        for base in sorted(used):
            meta = self.store.meta(base)
            self.sources.append({"name": "OSV export %s" % base, "url": meta.get("url", osvdata.EXPORT % base),
                                 "accessed_at": meta.get("last_modified") or meta.get("downloaded_at") or now()})
        return hits

    def record(self, osv_id, modified=None):
        if self.store is not None:
            return self.store.record(osv_id)
        name = "vulns/%s.json" % osv_id
        cached = self._cached(name)
        if cached is not None and (self.offline or modified is None or cached.get("modified") == modified):
            return cached
        if self.offline:
            raise LookupError("advisory %s is not in the offline cache" % osv_id)
        data = self.fetch(OSV_VULN + osv_id)
        self._store(name, data)
        return data

    def nvd(self, cpe_name):
        """All CVE records whose configurations mention this CPE (filtered later by nvd_matches)."""
        name = "nvd/%s.json" % re.sub(r"[^A-Za-z0-9._-]+", "_", cpe_name)
        cached = self._cached(name)
        if cached is not None or self.offline:
            if cached is None:
                raise LookupError("NVD results for %s are not in the offline cache" % cpe_name)
            return cached
        records, start = [], 0
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else None
        while True:
            url = "%s?virtualMatchString=%s&resultsPerPage=%d&startIndex=%d" % (
                NVD_API, urllib.parse.quote(cpe_name, safe=":*"), NVD_PAGE, start)
            page = self.fetch(url, None, headers=headers) if headers else self.fetch(url)
            records.extend(v["cve"] for v in page.get("vulnerabilities", []))
            start += page.get("resultsPerPage") or NVD_PAGE
            self.sleep(NVD_DELAY[bool(self.nvd_api_key)])
            if start >= page.get("totalResults", 0):
                break
        self._store(name, records)
        if not any(s["name"] == "NVD CVE API 2.0" for s in self.sources):
            self.sources.append({"name": "NVD CVE API 2.0", "url": NVD_API, "accessed_at": now()})
        return records

    def kev(self):
        cached = self._cached("kev.json")
        if self.offline:
            return cached or {}
        try:
            feed = self.fetch(KEV_FEED)
        except (urllib.error.URLError, OSError, ValueError):
            return cached or {}
        data = {v["cveID"]: {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                             "ransomware": v.get("knownRansomwareCampaignUse")} for v in feed.get("vulnerabilities", [])}
        self._store("kev.json", data)
        self.sources.append({"name": "CISA KEV", "url": KEV_FEED, "accessed_at": now()})
        return data

    def epss(self, cves):
        result = {}
        if self.offline or not cves:
            return result
        cves = sorted(cves)
        for start in range(0, len(cves), 100):
            try:
                data = self.fetch(EPSS_API + ",".join(cves[start:start + 100]))
            except (urllib.error.URLError, OSError, ValueError):
                return result
            for row in data.get("data", []):
                result[row["cve"]] = {"score": float(row["epss"]), "percentile": float(row["percentile"]), "date": row.get("date")}
        self.sources.append({"name": "FIRST EPSS", "url": EPSS_API.split("?")[0], "accessed_at": now()})
        return result


def osv_ecosystem(comp):
    """OSV names distribution ecosystems with their release, for example Debian:12 or Alpine:v3.19."""
    distro = comp.get("distro") or {}
    release = distro.get("release")
    eco = comp["ecosystem"]
    if not release:
        return eco
    if eco == "Ubuntu":
        # Unverified against OSV's full list: LTS releases carry an ':LTS' suffix.
        year, _, month = release.partition(".")
        return "Ubuntu:%s:LTS" % release if month == "04" and year.isdigit() and int(year) % 2 == 0 else "Ubuntu:" + release
    if eco in {"Debian", "Alpine"}:
        return "%s:%s" % (eco, release)
    return eco


def _in_range(version, entry):
    key = version_key(version)
    if key is None:
        return False
    checks = (("versionStartIncluding", lambda k, b: k >= b), ("versionStartExcluding", lambda k, b: k > b),
              ("versionEndIncluding", lambda k, b: k <= b), ("versionEndExcluding", lambda k, b: k < b))
    for field, ok in checks:
        bound = entry.get(field)
        if bound is not None:
            bound_key = version_key(bound)
            if bound_key is None or not ok(key, bound_key):
                return False
    return True


def nvd_matches(record, vendor, product, version):
    """Fixed versions if a vulnerable configuration entry names this vendor/product and contains the version,
    else None. NVD also returns CVEs that only mention the product as a platform; those are dropped."""
    matched, fixed = False, set()
    for config in record.get("configurations") or []:
        for node in config.get("nodes") or []:
            for entry in node.get("cpeMatch") or []:
                parts = entry.get("criteria", "").split(":")
                if not entry.get("vulnerable") or len(parts) < 6 or parts[3:5] != [vendor, product]:
                    continue
                if parts[5] not in ("*", "-"):
                    hit = version_key(parts[5]) == version_key(version)
                else:
                    hit = _in_range(version, entry)
                if hit:
                    matched = True
                    if entry.get("versionEndExcluding"):
                        fixed.add(entry["versionEndExcluding"])
    return sorted(fixed, key=lambda f: version_key(f) or (0,)) if matched else None


def nvd_advisory(record, component_id, cpe_name, fixed):
    metric = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        candidates = (record.get("metrics") or {}).get(key) or []
        metric = next((m for m in candidates if m.get("type") == "Primary"), candidates[0] if candidates else None)
        if metric:
            break
    vector = (metric or {}).get("cvssData", {}).get("vectorString")
    score = cvss3_score(vector)
    cwes = sorted({d["value"] for w in record.get("weaknesses") or [] for d in w.get("description") or []
                   if d.get("value", "").startswith("CWE-")})
    description = next((d["value"] for d in record.get("descriptions") or [] if d.get("lang") == "en"), "")
    return {
        "id": record["id"], "aliases": [], "summary": description[:140], "details": description,
        "published": record.get("published"), "modified": record.get("lastModified"),
        "withdrawn": record.get("lastModified") if record.get("vulnStatus") == "Rejected" else None,
        "severity": {"score": score, "vector": vector, "label": severity_label(score), "cwe": ", ".join(cwes) or None},
        "references": sorted({r["url"] for r in record.get("references") or [] if r.get("url")})[:20],
        "advisory_urls": ["https://nvd.nist.gov/vuln/detail/" + record["id"]],
        "affected": [{"component_id": component_id, "osv_ids": [], "ranges": ["NVD configuration for %s" % cpe_name],
                      "fixed": fixed}],
        "kev": None, "epss": None,
        "notes": ["Matched through NVD CPE configuration data, which is less precise than package-level advisories; "
                  "confirm the affected version range before reporting."],
    }


def canonical_id(ids):
    for prefix in ("CVE-", "GHSA-"):
        found = sorted(i for i in ids if i.startswith(prefix))
        if found:
            return found[0]
    return sorted(ids)[0]


def severity_of(records):
    """Pick the highest computable CVSS v3 score; fall back to a database severity label."""
    best = {"score": None, "vector": None, "label": None, "cwe": None}
    cwes = set()
    for rec in records:
        dbs = rec.get("database_specific") or {}
        cwes.update(dbs.get("cwe_ids") or [])
        for sev in rec.get("severity") or []:
            score = cvss3_score(sev.get("score")) if sev.get("type") == "CVSS_V3" else None
            if score is not None and (best["score"] is None or score > best["score"]):
                best.update(score=score, vector=sev["score"], label=severity_label(score))
            elif best["vector"] is None and sev.get("score"):
                best["vector"] = sev["score"]
        if best["label"] is None and isinstance(dbs.get("severity"), str):
            label = dbs["severity"].lower()
            best["label"] = "medium" if label == "moderate" else label
    best["cwe"] = ", ".join(sorted(cwes)) or None
    return best


def match_inventory(data, matcher, enrich=True):
    components = data["components"]
    queryable, unqueried, cpe_queryable = [], [], []
    for comp in components:
        if comp.get("root"):
            continue
        if not comp.get("version"):
            unqueried.append({"component_id": comp["id"], "reason": "version unknown" + (
                " (candidate range %s)" % comp["version_range"] if comp.get("version_range") else "")})
        elif comp.get("ecosystem") not in OSV_ECOSYSTEMS and comp.get("cpe"):
            cpe_queryable.append(comp)
        elif comp.get("ecosystem") not in OSV_ECOSYSTEMS:
            unqueried.append({"component_id": comp["id"], "reason": "no OSV ecosystem and no CPE to look up in NVD"})
        else:
            queryable.append(comp)
    # The root is queried too when it is itself a published package.
    root = next((c for c in components if c.get("root")), None)
    if root and root.get("version") and root.get("ecosystem") in OSV_ECOSYSTEMS:
        queryable.append(root)

    hits = matcher.query(queryable)
    by_id = {c["id"]: c for c in components}
    records, failures = {}, []
    for cid, found in hits.items():
        for osv_id, modified in found:
            if osv_id not in records:
                try:
                    records[osv_id] = matcher.record(osv_id, modified)
                except (LookupError, urllib.error.URLError, OSError, ValueError) as exc:
                    failures.append({"advisory": osv_id, "reason": str(exc)})

    # Union-find over IDs and aliases so one vulnerability becomes one advisory.
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for osv_id, rec in records.items():
        for alias in rec.get("aliases") or []:
            parent[find(alias)] = find(osv_id)
        find(osv_id)
    groups = {}
    for osv_id in records:
        groups.setdefault(find(osv_id), set()).add(osv_id)

    advisories = []
    for members in groups.values():
        recs = [records[m] for m in sorted(members)]
        ids = set(members)
        for rec in recs:
            ids.update(rec.get("aliases") or [])
        affected = {}
        for cid, found in hits.items():
            matched = [osv_id for osv_id, _ in found if osv_id in members]
            if not matched:
                continue
            comp = by_id[cid]
            entry = affected.setdefault(cid, {"component_id": cid, "osv_ids": [], "ranges": [], "fixed": []})
            entry["osv_ids"] = sorted(set(entry["osv_ids"]) | set(matched))
            for rec in recs:
                for aff in rec.get("affected") or []:
                    pkg = aff.get("package") or {}
                    if pkg.get("name") == comp["name"] and pkg.get("ecosystem", "").split(":")[0] == comp["ecosystem"]:
                        entry["ranges"] = sorted(set(entry["ranges"]) | set(ranges_text(aff)))
                        entry["fixed"] = sorted(set(entry["fixed"]) | set(fixed_versions_for(aff, comp["version"])),
                                                key=lambda f: version_key(f) or (0,))
        primary = next((r for r in recs if r.get("id", "").startswith("GHSA-")), recs[0])
        notes = []
        cves = sorted(i for i in ids if i.startswith("CVE-"))
        if len(cves) > 1:
            notes.append("Source records list %s as aliases of one another; verify whether they describe one "
                         "vulnerability before reporting them as a single finding." % ", ".join(cves))
        advisories.append({
            "id": canonical_id(ids),
            "aliases": sorted(ids - {canonical_id(ids)}),
            "summary": primary.get("summary") or "",
            "details": primary.get("details") or "",
            "published": min((r.get("published") for r in recs if r.get("published")), default=None),
            "modified": max((r.get("modified") for r in recs if r.get("modified")), default=None),
            "withdrawn": max((r.get("withdrawn") for r in recs if r.get("withdrawn")), default=None),
            "severity": severity_of(recs),
            "references": sorted({ref["url"] for r in recs for ref in r.get("references") or [] if ref.get("url")}),
            "advisory_urls": ["https://osv.dev/vulnerability/" + m for m in sorted(members)],
            "affected": sorted(affected.values(), key=lambda e: e["component_id"]),
            "kev": None,
            "epss": None,
            "notes": notes,
        })

    by_cve = {a["id"]: a for a in advisories}
    for comp in cpe_queryable:
        parts = comp["cpe"].split(":")
        cpe_name = ":".join(parts[:5] + [comp["version"]] + parts[6:])
        try:
            records_nvd = matcher.nvd(cpe_name)
        except (LookupError, urllib.error.URLError, OSError, ValueError) as exc:
            failures.append({"advisory": "NVD " + cpe_name, "reason": str(exc)})
            continue
        for record in records_nvd:
            fixed = nvd_matches(record, parts[3], parts[4], comp["version"])
            if fixed is None:
                continue
            adv = nvd_advisory(record, comp["id"], cpe_name, fixed)
            if adv["id"] in by_cve:
                by_cve[adv["id"]]["affected"].append(adv["affected"][0])
            else:
                by_cve[adv["id"]] = adv
                advisories.append(adv)

    if enrich:
        kev = matcher.kev()
        epss = matcher.epss({a["id"] for a in advisories if a["id"].startswith("CVE-")})
        for adv in advisories:
            adv["kev"] = kev.get(adv["id"])
            adv["epss"] = epss.get(adv["id"])

    def sort_key(adv):
        score = adv["severity"]["score"]
        label = adv["severity"]["label"] or "none"
        return (adv["kev"] is None, -(score if score is not None else -1),
                -SEVERITY_ORDER.index(label) if label in SEVERITY_ORDER else 0, adv["id"])

    advisories.sort(key=sort_key)
    return {
        "schema": "secdepth-matches",
        "schema_version": "1.0",
        "generated_at": now(),
        "producer": {"name": "secdepth-match", "version": VERSION},
        "root_component_id": data["root_component_id"],
        "data_sources": matcher.sources,
        "offline": matcher.offline,
        "components_queried": len(queryable) + len(cpe_queryable),
        "unqueried": unqueried,
        "lookup_failures": failures + matcher.not_comparable,
        "advisories": advisories,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inventory")
    parser.add_argument("--output", help="matches path (default: next to the inventory as matches.json)")
    parser.add_argument("--cache-dir", default=os.environ.get("SECDEPTH_CACHE", str(pathlib.Path.home() / ".cache" / "secdepth")))
    parser.add_argument("--offline", action="store_true", help="use only the cache; never touch the network")
    parser.add_argument("--osv-data", help="match against OSV exports downloaded with osvdata.py (implies --offline)")
    parser.add_argument("--no-enrich", action="store_true", help="skip CISA KEV and EPSS")
    args = parser.parse_args(argv)
    try:
        data = inventory.load(args.inventory)
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    matcher = Matcher(cache_dir=args.cache_dir, offline=args.offline, nvd_api_key=os.environ.get("NVD_API_KEY"),
                      osv_data=args.osv_data)
    try:
        result = match_inventory(data, matcher, enrich=not args.no_enrich)
    except (urllib.error.URLError, OSError) as exc:
        print("advisory lookup failed: %s" % exc, file=sys.stderr)
        return 1
    out = pathlib.Path(args.output) if args.output else pathlib.Path(args.inventory).with_name("matches.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("%s: %d advisories across %d queried components; %d not queried; %d lookup failures" % (
        out, len(result["advisories"]), result["components_queried"], len(result["unqueried"]), len(result["lookup_failures"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
