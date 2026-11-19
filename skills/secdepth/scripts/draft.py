#!/usr/bin/env python3
"""Build a secdepth draft report from an inventory, matches and checks, without a language model.

Usage: draft.py <inventory.json> <matches.json> <checks.json> [--output FILE]

The draft uses the report schema read by render_report.py. Verdicts come from check.py; the model's
job afterwards is to review `conditional` findings and findings with notes, not to build the draft.
"""
import argparse
import datetime
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import check  # noqa: E402
import inventory  # noqa: E402

ORDER = {"reachable": 3, "conditional": 2, "unknown": 1, "not-reachable": 0}
MAX_DESCRIPTION = 900
MAX_REFERENCES = 6


def semver_compatible(current, fixed):
    """True when `fixed` is a newer release on the same compatible line: same major, or same minor for 0.x."""
    def parts(v):
        nums = [int(n) for n in re.findall(r"\d+", (v or "").lstrip("vV").split("-", 1)[0].split("+", 1)[0])[:3]]
        return nums + [0] * (3 - len(nums)) if nums else None
    cur, fix = parts(current), parts(fixed)
    if cur is None or fix is None or fix <= cur:
        return False
    return fix[0] == cur[0] and (cur[0] != 0 or fix[1] == cur[1])


def access_date(value):
    return (value or datetime.date.today().isoformat())[:10]


def build(data, matches, checks):
    components = {c["id"]: c for c in data["components"]}
    root_id = data["root_component_id"]
    is_artifact = data["target"]["kind"] == "artifact"
    by_pair = {(r["advisory_id"], r["component_id"]): r for r in checks["results"]}
    accessed = access_date(matches.get("generated_at"))
    sources, findings = {}, []

    def add_source(sid, url, publisher, kind, supports):
        if url.startswith(("http://", "https://")) and sid not in sources:
            sources[sid] = {"id": sid, "url": url, "publisher": publisher, "type": kind, "accessed_at": accessed,
                            "supports": supports}
        return sid

    for adv in matches["advisories"]:
        results = [by_pair[(adv["id"], aff["component_id"])] for aff in adv["affected"]
                   if (adv["id"], aff["component_id"]) in by_pair]
        if not results:
            continue
        urls = adv.get("advisory_urls") or adv.get("osv_urls") or []
        source_ids = [add_source(("nvd-" if "nvd.nist.gov" in url else "osv-") + url.rsplit("/", 1)[-1].lower(), url,
                                 "NVD" if "nvd.nist.gov" in url else "OSV.dev", "advisory", adv["summary"][:200])
                      for url in urls]
        for i, ref in enumerate(adv["references"][:MAX_REFERENCES]):
            source_ids.append(add_source("%s-ref%d" % (adv["id"].lower(), i + 1), ref, ref.split("/")[2], "reference",
                                         "Reference listed by the advisory"))

        exposed = [r for r in results if r["scope"] not in {"dev", "build"} or r["component_id"] == root_id]
        withdrawn = bool(adv.get("withdrawn"))
        applicability = "affected" if exposed and not withdrawn else "not-affected"
        strongest = max(results, key=lambda r: ORDER.get(r["proposed_reachability"], 1))
        reachability = strongest["proposed_reachability"]
        confidence = strongest["confidence"] if len(results) == 1 else min(
            (r["confidence"] for r in results), key=["low", "medium", "high"].index)

        evidence, paths, dev_parents = [], [], set()
        for r in results:
            evidence.extend("%s: %s" % (r["component_id"], e) for e in r["evidence"])
            evidence.extend("%s: imported at %s:%d (%s)" % (r["component_id"], h["file"], h["line"], h["text"])
                            for h in r["call_sites"][:5])
            ancestors = check.direct_ancestors(data, r["component_id"])
            if exposed:
                # Runtime findings show only the paths that ship; dev routes to the same package are noise.
                ancestors = {p: path for p, path in ancestors.items() if components[p].get("scope") not in {"dev", "build"}}
            else:
                dev_parents.update(components[p]["name"] for p in ancestors)
            paths.extend(ancestors.values() or [[root_id]])
        if not paths:
            paths = [[root_id]]

        fixed = sorted({f for aff in adv["affected"] for f in aff.get("fixed", [])})
        first_fixed = ", ".join("%s %s" % (components[aff["component_id"]]["name"], aff["fixed"][0])
                                for aff in adv["affected"] if aff.get("fixed"))
        fix = next((r["fix_check"] for r in results if r.get("fix_check")), None)
        if exposed and fix and fix.get("advisory_cleared"):
            upgraded = ", ".join("%s %s" % (name, "/".join(vs)) for name, vs in sorted(fix.get("upgrade_resolved", {}).items()) if vs) \
                or fix["upgrade"]
            pulled = ", ".join("%s %s" % (components[r["component_id"]]["name"], v)
                               for r in results if r.get("fix_check")
                               if components[r["component_id"]]["name"] not in fix.get("upgrade_resolved", {})
                               for v in r["fix_check"]["resolved_versions"] if v != "not installed")
            target = "%s (resolves %s)" % (upgraded, pulled) if pulled else upgraded
            recommendation = "Upgrade to %s (newest release in the current major version, %s). A fresh resolution on %s " \
                             "no longer matches this advisory." % (upgraded, fix["upgrade"], fix["checked_at"][:10])
            feasibility = "feasible"
        elif fixed and is_artifact:
            target = first_fixed
            recommendation = "Rebuild the artifact with, or obtain a vendor build that includes, %s." % target
            feasibility = "feasible"
        elif fixed:
            compatible = [(components[aff["component_id"]], f) for aff in adv["affected"] for f in aff.get("fixed", [])
                          if semver_compatible(components[aff["component_id"]].get("version"), f)]
            if compatible and len({c["id"] for c, _ in compatible}) == len(adv["affected"]):
                target = ", ".join(sorted({"%s %s" % (c["name"], f) for c, f in compatible}))
                recommendation = "Update to %s, a semver-compatible release that fixes this advisory. The update was " \
                                 "not verified by resolving it." % target
                feasibility = "feasible"
            else:
                target = first_fixed
                recommendation = "Upgrade to a fixed version: %s. It may need a breaking (major) upgrade; the upgrade " \
                                 "path was not verified." % target
                feasibility = "unknown"
        else:
            target, recommendation, feasibility = "unknown", "No fixed version is published in the advisory data.", "unknown"
        if not exposed:
            target = first_fixed or "unknown"
            recommendation = "No action for consumers of the published package. For contributors, upgrade the " \
                             "development dependency %s so it resolves %s." % (
                                 ", ".join(sorted(dev_parents)) or "that brings it in", first_fixed or "a fixed version")
            feasibility = "feasible" if first_fixed else "unknown"
        if withdrawn:
            recommendation = "No action needed; the advisory was withdrawn. Suppress stale scanner results, citing the withdrawal."

        description = " ".join(adv.get("details", "").replace("#", " ").split()) or adv["summary"]
        if len(description) > MAX_DESCRIPTION:
            description = description[:MAX_DESCRIPTION].rsplit(" ", 1)[0] + " …"
        extras = list(adv.get("notes") or [])
        if adv.get("kev"):
            extras.append("Listed in the CISA Known Exploited Vulnerabilities catalog (added %s)." % adv["kev"]["date_added"])
        if adv.get("epss"):
            extras.append("EPSS %.4f (percentile %.2f) on %s." % (adv["epss"]["score"], adv["epss"]["percentile"],
                                                                 adv["epss"].get("date") or accessed))
        if extras:
            description += " " + " ".join(extras)

        sev = adv["severity"]
        findings.append({
            "id": adv["id"],
            "summary": adv["summary"] + (" (%s)" % ", ".join(adv["aliases"]) if adv["aliases"] else ""),
            "description": description,
            "applicability": applicability,
            "affected_component_ids": [r["component_id"] for r in results],
            "affected_ranges": sorted({rng for aff in adv["affected"] for rng in aff.get("ranges", [])}),
            "cvss": {"score": sev.get("score"), "severity": sev.get("label"), "vector": sev.get("vector"), "cwe": sev.get("cwe")},
            "exploitability": {"presence": "present", "reachability": reachability, "attack_preconditions": [],
                               "evidence": evidence, "confidence": confidence},
            "update_status": "released" if fixed or (fix and fix.get("advisory_cleared")) else "unknown",
            "recommended_target_version": target,
            "feasibility": feasibility,
            "patch_eta": {"date": None, "certainty": "confirmed" if fixed else "unknown", "source_ids": source_ids[:1]},
            "blockers": [],
            "recommendation": recommendation,
            "temporary_mitigations": [],
            "dependency_paths": [list(p) for p in {tuple(p) for p in paths}],
            "claims": [{"claim": "Advisory data, affected ranges and fixed versions", "source_ids": source_ids[:len(urls)]}],
            "sources": source_ids,
            "review": {"needed": reachability in {"conditional", "unknown"} or bool(adv.get("notes")),
                       "reason": "%s reachability" % reachability if reachability in {"conditional", "unknown"} else
                                 ("matcher notes" if adv.get("notes") else None)},
        })

    root = components[root_id]
    summary = inventory.coverage_summary(data)
    report = {
        "report": {
            "title": "%s: %s %s" % ("Artifact scan" if is_artifact else "Project scan", root["name"], root.get("version") or ""),
            "generated_at": matches.get("generated_at") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "root_component_id": root_id,
            "target": {
                "mode": "artifact-scan" if is_artifact else "project-scan",
                "path": data["target"]["path"], "ref": data["target"].get("ref"),
                "components_checked": len(data["components"]),
                "runtime_components": sum(1 for c in data["components"] if c.get("scope") == "runtime"),
                "coverage": summary, "coverage_complete": data["coverage"]["complete"],
                "resolution": data.get("resolution", []),
                "advisory_sources": [s["name"] for s in matches.get("data_sources", [])],
                "offline": matches.get("offline", False),
                "not_queried": matches.get("unqueried", []),
                "lookup_failures": matches.get("lookup_failures", []),
                "shipped_files_rule": checks.get("shipped_files_rule"),
                "pipeline": "secdepth resolve/match/check/draft; model review pending",
            },
        },
        "components": [{k: c.get(k) for k in ("id", "name", "ecosystem", "version", "manifest", "direct", "root", "scope", "depends_on")}
                       for c in data["components"]],
        "sources": list(sources.values()),
        "vulnerabilities": findings,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inventory")
    parser.add_argument("matches")
    parser.add_argument("checks")
    parser.add_argument("--output", help="draft path (default: next to the checks as draft.json)")
    args = parser.parse_args(argv)
    try:
        data = inventory.load(args.inventory)
        matches = json.loads(pathlib.Path(args.matches).read_text(encoding="utf-8"))
        checks = json.loads(pathlib.Path(args.checks).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    report = build(data, matches, checks)
    out = pathlib.Path(args.output) if args.output else pathlib.Path(args.checks).with_name("draft.json")
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    review = sum(1 for f in report["vulnerabilities"] if f["review"]["needed"])
    print("%s: %d findings; %d need model review" % (out, len(report["vulnerabilities"]), review))
    return 0


if __name__ == "__main__":
    sys.exit(main())
