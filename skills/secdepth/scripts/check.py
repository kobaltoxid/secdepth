#!/usr/bin/env python3
"""Collect reachability evidence for matched advisories, without a language model.

Usage: check.py <inventory.json> <matches.json> <project-dir> [--output FILE] [--fix-check]

For every advisory and affected component it records scope, whether the code ships, call sites of
the vulnerable package in shipped project code (file:line), functions the advisory names, and a
proposed reachability verdict. `--fix-check` (npm only, needs network) resolves the newest version
of each direct dependency in a temporary copy and reports whether it clears the vulnerable version.
"""
import argparse
import collections
import datetime
import fnmatch
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import inventory  # noqa: E402
import match  # noqa: E402

VERSION = "0.1.0"
CODE_SUFFIXES = {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}
SKIP_DIRS = {".git", "node_modules", "security-findings", "__pycache__", "coverage"}
MAX_HITS = 20
# Words that look like identifiers in advisory text but are not useful to search for.
GENERIC = {"true", "false", "null", "undefined", "object", "string", "array", "function", "toString", "length",
           "__proto__", "constructor", "prototype", "json", "url", "http", "https"}
# Built-in receivers: `JSON.parse` in an advisory says nothing about the vulnerable package.
BUILTIN_RECEIVERS = {"JSON", "Object", "Array", "Math", "Promise", "console", "Buffer", "String", "Number", "Date", "process"}
FILE_SUFFIXES = (".js", ".ts", ".json", ".py", ".md", ".mjs", ".cjs", ".yml", ".yaml", ".txt")
# Advisories say `response.redirect()`; code says `res.redirect`.
RECEIVER_ALIASES = {"response": ["res"], "request": ["req"]}


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def shipped_matcher(project):
    """Return (predicate, reason) deciding whether a project-relative path is published."""
    manifest = project / "package.json"
    if manifest.is_file():
        files = json.loads(manifest.read_text(encoding="utf-8")).get("files")
        if isinstance(files, list) and files:
            patterns = [f.rstrip("/") for f in files]

            def shipped(rel):
                text = rel.as_posix()
                return any(text == p or text.startswith(p + "/") or fnmatch.fnmatch(text, p) for p in patterns)
            return shipped, 'package.json "files" publishes only: %s' % ", ".join(files)
    return (lambda rel: True), "no package.json \"files\" field; every project file is treated as shipped"


def code_files(project):
    for path in sorted(project.rglob("*")):
        rel = path.relative_to(project)
        if path.is_file() and path.suffix in CODE_SUFFIXES and not any(p in SKIP_DIRS for p in rel.parts):
            yield rel


def import_pattern(name):
    quoted = re.escape(name)
    return re.compile(r"""(?:require\s*\(\s*|from\s+|import\s*\(\s*|import\s+)['"]%s(?:/[^'"]*)?['"]""" % quoted)


def function_tokens(text):
    """Code identifiers the advisory names in backticks, such as `qs.stringify()` or `res.redirect()`."""
    tokens = set()
    for raw in re.findall(r"`([^`\n]{2,80})`", text or ""):
        m = re.match(r"^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*(\(\))?$", raw.strip())
        if not m:
            continue
        token = m.group(1)
        if token.split(".")[-1] in GENERIC or (len(token) < 4 and "." not in token):
            continue
        if raw.strip().endswith(FILE_SUFFIXES) or token.split(".")[0] in BUILTIN_RECEIVERS:
            continue
        if "." in token or m.group(2):
            tokens.add(token)
    return sorted(tokens)


def search(project, files, pattern):
    hits = []
    for rel in files:
        try:
            lines = (project / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            # Comments and doc blocks describe code; they are not calls or definitions.
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if pattern.search(line):
                hits.append({"file": rel.as_posix(), "line": number, "text": line.strip()[:160]})
                if len(hits) >= MAX_HITS:
                    return hits
    return hits


def method_pattern(token):
    """Match the full dotted name (and receiver aliases) as a call or a definition; never the bare method name,
    which would confuse `qs.stringify` with `JSON.stringify`."""
    parts = token.split(".")
    names = [token]
    if len(parts) > 1 and parts[0] in RECEIVER_ALIASES:
        names += [".".join([alias] + parts[1:]) for alias in RECEIVER_ALIASES[parts[0]]]
    alternatives = []
    for name in names:
        escaped = re.escape(name)
        alternatives.append(r"(?<![\w$.])%s\s*(?:\(|=\s*function)" % escaped)
    if len(parts) == 1:
        alternatives.append(r"function\s+%s\s*\(" % re.escape(token))
    return re.compile("|".join(alternatives))


def direct_ancestors(data, component_id):
    """Direct dependencies of the root whose subtree contains the component, with one path each."""
    graph = {c["id"]: c.get("depends_on") or [] for c in data["components"]}
    root = data["root_component_id"]
    result = {}
    for direct in graph.get(root, []):
        queue = collections.deque([[direct]])
        seen = {direct}
        while queue:
            path = queue.popleft()
            if path[-1] == component_id:
                result[direct] = [root] + path
                break
            for nxt in graph.get(path[-1], []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append(path + [nxt])
    return result


def check(data, matches, project, fix_results=None):
    project = pathlib.Path(project)
    components = {c["id"]: c for c in data["components"]}
    root_id = data["root_component_id"]
    shipped, shipped_reason = shipped_matcher(project)
    files = list(code_files(project))
    shipped_files = [f for f in files if shipped(f)]
    import_cache = {}

    def imports_of(name):
        if name not in import_cache:
            pattern = import_pattern(name)
            import_cache[name] = {"shipped": search(project, shipped_files, pattern),
                                  "unshipped": search(project, [f for f in files if not shipped(f)], pattern)}
        return import_cache[name]

    results = []
    for adv in matches["advisories"]:
        tokens = function_tokens((adv.get("summary") or "") + "\n" + (adv.get("details") or ""))
        function_hits = {t: search(project, shipped_files, method_pattern(t)) for t in tokens}
        for aff in adv["affected"]:
            comp = components.get(aff["component_id"])
            if comp is None:
                continue
            evidence, call_sites = [], []
            if adv.get("withdrawn"):
                verdict, confidence = "not-reachable", "high"
                evidence.append("Advisory withdrawn on %s." % adv["withdrawn"][:10])
            elif comp["id"] == root_id:
                verdict, confidence = "conditional", "medium"
                evidence.append("The vulnerable code is the project itself (%s)." % comp["id"])
            elif comp.get("scope") in {"dev", "build"}:
                verdict, confidence = "not-reachable", "high"
                evidence.append("%s is a %s-only dependency; it is not installed for consumers of the published package."
                                % (comp["id"], comp["scope"]))
                for parent, path in direct_ancestors(data, comp["id"]).items():
                    hits = imports_of(components[parent]["name"])
                    used = hits["shipped"] + hits["unshipped"]
                    evidence.append("Pulled in by %s via %s; %s." % (
                        components[parent]["name"], " > ".join(path),
                        ("required or imported in " + ", ".join(sorted({h["file"] for h in used}))) if used
                        else "not required or imported by any project code file"))
            else:
                ancestors = {p: path for p, path in direct_ancestors(data, comp["id"]).items()
                             if components[p].get("scope") not in {"dev", "build"}}
                for parent, path in sorted(ancestors.items()):
                    hits = imports_of(components[parent]["name"])
                    call_sites.extend(dict(h, via=components[parent]["name"]) for h in hits["shipped"])
                    if parent != comp["id"]:
                        evidence.append("Transitive via %s." % " > ".join(path))
                if call_sites:
                    verdict, confidence = "conditional", "medium"
                    evidence.append("Shipped code imports the package or the direct dependency that brings it in (%d call sites)."
                                    % len(call_sites))
                else:
                    verdict, confidence = "not-reachable", "medium"
                    evidence.append("No shipped project file imports %s or a direct dependency that brings it in." % comp["name"])
            for token, hits in function_hits.items():
                if hits:
                    evidence.append("Advisory names `%s`; found in shipped code at %s." % (
                        token, ", ".join("%s:%d" % (h["file"], h["line"]) for h in hits[:5])))
                else:
                    evidence.append("Advisory names `%s`; no call or definition found in shipped code." % token)
            fix = (fix_results or {}).get((adv["id"], comp["id"]))
            results.append({
                "advisory_id": adv["id"], "component_id": comp["id"], "scope": comp.get("scope"),
                "direct": comp.get("direct"), "presence": "present", "proposed_reachability": verdict,
                "confidence": confidence, "evidence": evidence, "call_sites": call_sites[:MAX_HITS],
                "function_hits": {t: h[:5] for t, h in function_hits.items()}, "fixed_versions": aff.get("fixed", []),
                "fix_check": fix,
            })
    return {
        "schema": "secdepth-checks", "schema_version": "1.0", "generated_at": now(),
        "producer": {"name": "secdepth-check", "version": VERSION},
        "project": str(project), "shipped_files_rule": shipped_reason,
        "code_files_scanned": len(files), "shipped_code_files": len(shipped_files),
        "results": results,
    }


def fix_check(data, matches, project, matcher):
    """Resolve the newest version of each relevant direct dependency in a temporary copy (npm only)."""
    npm = shutil.which("npm")
    if not npm:
        return {}, "npm is not installed"
    components = {c["id"]: c for c in data["components"]}
    root = components[data["root_component_id"]]
    direct_names = sorted({components[d]["name"] for d in root.get("depends_on", []) if components[d].get("scope") == "runtime"})
    def same_major(comp):
        # "^x.y.z" resolves the newest release without a breaking major upgrade.
        return "^" + comp["version"] if match.version_key(comp.get("version") or "") else "latest"

    by_name = {c["name"]: c for c in data["components"] if not c.get("root")}
    if root.get("version") and root.get("ecosystem") == "npm" and not (pathlib.Path(project) / "package-lock.json").exists():
        # A published library: check what consumers get from its newest release in the same major version.
        manifest = {"name": "secdepth-fix-check", "version": "0.0.0", "dependencies": {root["name"]: same_major(root)}}
    else:
        manifest = {"name": "secdepth-fix-check", "version": "0.0.0",
                    "dependencies": {n: same_major(by_name[n]) for n in direct_names}}
    with tempfile.TemporaryDirectory(prefix="secdepth-fix-") as tmp:
        (pathlib.Path(tmp) / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
        proc = subprocess.run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                              cwd=tmp, capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            return {}, "npm could not resolve the upgrade: " + (proc.stderr.strip().splitlines() or ["unknown"])[-1]
        lock = json.loads((pathlib.Path(tmp) / "package-lock.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import resolve  # noqa: E402
    _, upgraded, _ = resolve.npm_components(lock, "upgrade-probe", "high")
    probe = inventory.new_inventory("secdepth-check", VERSION, "source", "upgrade-probe", "npm:secdepth-fix-check@0.0.0")
    probe["components"] = upgraded
    after = match.match_inventory(probe, matcher, enrich=False)
    remaining = {(a["id"], aff["component_id"].split("@")[0]) for a in after["advisories"] for aff in a["affected"]}
    versions = {}
    for comp in upgraded:
        versions.setdefault(comp["name"], set()).add(comp["version"])
    target = ", ".join("%s@%s" % (k, v) for k, v in sorted(manifest["dependencies"].items()))
    upgraded_to = {name: sorted(versions.get(name, [])) for name in manifest["dependencies"]}
    results = {}
    for adv in matches["advisories"]:
        for aff in adv["affected"]:
            name = components[aff["component_id"]]["name"]
            cleared = (adv["id"], aff["component_id"].split("@")[0]) not in remaining
            results[(adv["id"], aff["component_id"])] = {
                "upgrade": target, "upgrade_resolved": upgraded_to,
                "resolved_versions": sorted(versions.get(name, [])) or ["not installed"],
                "advisory_cleared": cleared, "checked_at": now(),
            }
    return results, None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("inventory")
    parser.add_argument("matches")
    parser.add_argument("project")
    parser.add_argument("--output", help="checks path (default: next to the matches as checks.json)")
    parser.add_argument("--fix-check", action="store_true", help="resolve upgrades with npm and re-match (network)")
    parser.add_argument("--cache-dir", default=None, help="advisory cache for --fix-check (default: match.py's)")
    args = parser.parse_args(argv)
    try:
        data = inventory.load(args.inventory)
        matches = json.loads(pathlib.Path(args.matches).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        return 1
    fixes, note = {}, None
    if args.fix_check:
        cache = args.cache_dir or str(pathlib.Path.home() / ".cache" / "secdepth")
        fixes, note = fix_check(data, matches, args.project, match.Matcher(cache_dir=cache))
    result = check(data, matches, args.project, fixes)
    if note:
        result["fix_check_note"] = note
    out = pathlib.Path(args.output) if args.output else pathlib.Path(args.matches).with_name("checks.json")
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    counts = collections.Counter(r["proposed_reachability"] for r in result["results"])
    print("%s: %d advisory-component pairs; %s" % (out, len(result["results"]), dict(counts)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
