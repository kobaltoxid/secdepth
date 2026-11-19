#!/usr/bin/env python3
"""Validate and build secdepth component inventories (references/inventory-schema.json).

Usage: inventory.py <inventory.json>   # prints problems and exits 1 if any
"""
import datetime
import json
import pathlib
import sys

SCHEMA = "secdepth-inventory"
SCHEMA_VERSION = "1.0"
SCOPES = {"runtime", "dev", "build", "optional", "peer", "unknown"}
CONFIDENCE = {"exact", "high", "medium", "low"}
COVERAGE_STATUS = {"identified", "unidentified", "unpack-failed", "skipped", "tool-missing"}
TARGET_KINDS = {"source", "artifact"}


def component_id(ecosystem, name, version):
    return "%s:%s@%s" % (ecosystem, name, version if version else "unknown")


def new_inventory(producer, producer_version, kind, path, root_component_id, ref=None, sha256=None):
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {"name": producer, "version": producer_version},
        "target": {"kind": kind, "path": path, "ref": ref, "sha256": sha256},
        "root_component_id": root_component_id,
        "components": [],
        "coverage": {"complete": True, "entries": [], "tools": []},
        "resolution": [],
    }


def coverage_summary(inventory):
    counts = {}
    for entry in inventory.get("coverage", {}).get("entries", []):
        counts[entry.get("status")] = counts.get(entry.get("status"), 0) + 1
    return counts


def validate(data):
    """Return a list of problems; an empty list means the inventory is usable."""
    if not isinstance(data, dict):
        return ["top level: expected an object"]
    errors = []

    def need(obj, key, kind, where):
        value = obj.get(key)
        if not isinstance(value, kind) or (kind is not bool and isinstance(value, bool)):
            errors.append("%s.%s: expected %s" % (where, key, kind.__name__))
            return None
        return value

    if data.get("schema") != SCHEMA:
        errors.append("schema: expected %r" % SCHEMA)
    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version: expected %r" % SCHEMA_VERSION)
    need(data, "generated_at", str, "inventory")
    producer = need(data, "producer", dict, "inventory")
    if producer is not None:
        need(producer, "name", str, "producer")
        need(producer, "version", str, "producer")
    target = need(data, "target", dict, "inventory")
    if target is not None:
        if target.get("kind") not in TARGET_KINDS:
            errors.append("target.kind: expected one of %s" % ", ".join(sorted(TARGET_KINDS)))
        need(target, "path", str, "target")
    root_id = need(data, "root_component_id", str, "inventory")

    ids = set()
    components = need(data, "components", list, "inventory") or []
    for i, c in enumerate(components):
        where = "components[%d]" % i
        if not isinstance(c, dict):
            errors.append(where + ": expected an object")
            continue
        cid = need(c, "id", str, where)
        if cid in ids:
            errors.append("%s.id: duplicate %r" % (where, cid))
        ids.add(cid)
        need(c, "name", str, where)
        need(c, "ecosystem", str, where)
        if c.get("scope") not in SCOPES:
            errors.append("%s.scope: expected one of %s" % (where, ", ".join(sorted(SCOPES))))
        version = c.get("version")
        if version is not None and not isinstance(version, str):
            errors.append(where + ".version: expected a string or null")
        evidence = need(c, "evidence", list, where)
        if evidence is not None and not evidence:
            errors.append(where + ".evidence: at least one evidence entry is required")
        for j, e in enumerate(evidence or []):
            ewhere = "%s.evidence[%d]" % (where, j)
            if not isinstance(e, dict):
                errors.append(ewhere + ": expected an object")
                continue
            need(e, "identifier", str, ewhere)
            need(e, "location", str, ewhere)
            if e.get("confidence") not in CONFIDENCE:
                errors.append("%s.confidence: expected one of %s" % (ewhere, ", ".join(sorted(CONFIDENCE))))
    for i, c in enumerate(components):
        if isinstance(c, dict):
            for dep in c.get("depends_on") or []:
                if dep not in ids:
                    errors.append("components[%d].depends_on: unknown component %r" % (i, dep))
    if root_id is not None and root_id not in ids:
        errors.append("root_component_id: %r is not a component" % root_id)

    coverage = need(data, "coverage", dict, "inventory")
    if coverage is not None:
        need(coverage, "complete", bool, "coverage")
        for i, entry in enumerate(need(coverage, "entries", list, "coverage") or []):
            where = "coverage.entries[%d]" % i
            if not isinstance(entry, dict):
                errors.append(where + ": expected an object")
                continue
            need(entry, "path", str, where)
            if entry.get("status") not in COVERAGE_STATUS:
                errors.append("%s.status: expected one of %s" % (where, ", ".join(sorted(COVERAGE_STATUS))))
        incomplete = [e for e in coverage.get("entries") or []
                      if isinstance(e, dict) and e.get("status") in {"unidentified", "unpack-failed", "tool-missing"}]
        if coverage.get("complete") is True and incomplete:
            errors.append("coverage.complete: true, but %d entries are unidentified, failed or missing a tool" % len(incomplete))
    return errors


def load(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    problems = validate(data)
    if problems:
        raise ValueError("invalid inventory %s:\n  %s" % (path, "\n  ".join(problems)))
    return data


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    try:
        data = json.loads(pathlib.Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print("cannot read %s: %s" % (args[0], exc), file=sys.stderr)
        return 1
    problems = validate(data)
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print("valid: %d components, coverage %s" % (len(data["components"]), coverage_summary(data)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
