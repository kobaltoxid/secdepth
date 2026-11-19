#!/usr/bin/env python3
"""Resolve a source project's full dependency tree into a secdepth inventory, without a language model.

Usage: resolve.py <project-dir> [--output FILE] [--no-generate]

Supported: npm (package-lock.json / npm-shrinkwrap.json; otherwise a lockfile is generated in a
temporary copy with install scripts disabled). Manifests of other ecosystems are listed in the
coverage ledger as not yet supported instead of being skipped silently.
"""
import argparse
import datetime
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import inventory  # noqa: E402

VERSION = "0.1.0"
NPM_LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json")
# Manifests whose resolvers are planned but not implemented yet.
PLANNED = {
    "yarn.lock": "yarn lockfile parsing is not implemented yet",
    "pnpm-lock.yaml": "pnpm lockfile parsing is not implemented yet",
    "requirements.txt": "PyPI resolution is not implemented yet",
    "pyproject.toml": "PyPI resolution is not implemented yet",
    "poetry.lock": "PyPI resolution is not implemented yet",
    "uv.lock": "PyPI resolution is not implemented yet",
    "pom.xml": "Maven resolution is not implemented yet",
    "build.gradle": "Gradle resolution is not implemented yet",
    "build.gradle.kts": "Gradle resolution is not implemented yet",
    "go.mod": "Go resolution is not implemented yet",
    "Cargo.lock": "Cargo resolution is not implemented yet",
    "packages.lock.json": "NuGet resolution is not implemented yet",
}
SKIP_DIRS = {".git", "node_modules", "security-findings", "__pycache__", ".venv", "venv", "vendor", "dist", "build"}


def npm_purl(name, version):
    return "pkg:npm/%s@%s" % (urllib.parse.quote(name, safe="/"), urllib.parse.quote(version, safe=""))


def find_manifests(root):
    """Yield project-relative manifest paths, ignoring dependency and output folders."""
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]) or not path.is_file():
            continue
        if path.name in PLANNED or path.name == "package.json":
            yield rel


def generate_npm_lock(project, notes):
    """Resolve package.json in a temporary copy; the project itself is never modified."""
    npm = shutil.which("npm")
    if not npm:
        return None, "npm is not installed"
    with tempfile.TemporaryDirectory(prefix="secdepth-npm-") as tmp:
        shutil.copy2(project / "package.json", pathlib.Path(tmp) / "package.json")
        proc = subprocess.run(
            [npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
            cwd=tmp, capture_output=True, text=True, timeout=600,
        )
        lock = pathlib.Path(tmp) / "package-lock.json"
        if proc.returncode != 0 or not lock.exists():
            return None, "npm could not resolve package.json: " + (proc.stderr.strip().splitlines() or ["unknown error"])[-1]
        notes.append("No npm lockfile is committed; resolved package.json with npm %s using "
                     "--package-lock-only --ignore-scripts in a temporary copy on %s. Ranged versions reflect "
                     "the registry on that date." % (_npm_version(npm), datetime.date.today().isoformat()))
        return json.loads(lock.read_text(encoding="utf-8")), None


def _npm_version(npm):
    try:
        return subprocess.run([npm, "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def npm_components(lock, lock_label, confidence):
    """Convert a lockfile v2/v3 'packages' map into inventory components and a root."""
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("lockfile has no 'packages' map (lockfileVersion 1 is not supported)")
    root_meta = packages.get("", {})
    root_deps = set(root_meta.get("dependencies", {})) | set(root_meta.get("devDependencies", {})) \
        | set(root_meta.get("optionalDependencies", {})) | set(root_meta.get("peerDependencies", {}))

    def resolve(from_path, name):
        base = from_path
        while True:
            candidate = (base + "/" if base else "") + "node_modules/" + name
            if candidate in packages:
                return candidate
            if not base:
                return None
            cut = base.rfind("/node_modules/")
            base = base[:cut] if cut >= 0 else ""

    def label(path):
        meta = packages[path]
        return inventory.component_id("npm", meta.get("name") or path.split("node_modules/")[-1], meta.get("version"))

    root_name = root_meta.get("name") or lock.get("name") or "root"
    root_id = inventory.component_id("npm", root_name, root_meta.get("version") or lock.get("version"))
    components = {root_id: {
        "id": root_id, "name": root_name, "ecosystem": "npm", "version": root_meta.get("version") or lock.get("version"),
        "purl": npm_purl(root_name, root_meta.get("version") or "0.0.0"), "scope": "runtime", "direct": None,
        "root": True, "manifest": "package.json", "depends_on": [],
        "evidence": [{"identifier": "package.json", "location": "package.json", "detail": "name and version", "confidence": "exact"}],
    }}
    skipped = []
    for path, meta in packages.items():
        if not path:
            continue
        if meta.get("link") or "version" not in meta:
            skipped.append((path, "workspace link or entry without a version"))
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        cid = label(path)
        if meta.get("dev") or meta.get("devOptional"):
            scope = "dev"
        elif meta.get("optional"):
            scope = "optional"
        elif meta.get("peer"):
            scope = "peer"
        else:
            scope = "runtime"
        top_level = path == "node_modules/" + name
        comp = components.get(cid)
        if comp is None:
            comp = components[cid] = {
                "id": cid, "name": name, "ecosystem": "npm", "version": meta["version"], "purl": npm_purl(name, meta["version"]),
                "scope": scope, "direct": top_level and name in root_deps, "root": False, "manifest": lock_label,
                "depends_on": [], "evidence": [],
            }
        elif comp["scope"] != "runtime" and scope == "runtime":
            comp["scope"] = "runtime"
        comp["direct"] = comp["direct"] or (top_level and name in root_deps)
        comp["evidence"].append({"identifier": "npm-lockfile", "location": "%s#%s" % (lock_label, path),
                                 "detail": meta.get("resolved") or meta["version"], "confidence": confidence})
        deps = dict(meta.get("dependencies", {}))
        deps.update(meta.get("optionalDependencies", {}))
        for dep in deps:
            target = resolve(path, dep)
            if target and target != path and label(target) not in comp["depends_on"]:
                comp["depends_on"].append(label(target))
    for dep in root_deps:
        target = resolve("", dep)
        if target and label(target) not in components[root_id]["depends_on"]:
            components[root_id]["depends_on"].append(label(target))
    for comp in components.values():
        comp["depends_on"].sort()
    return root_id, list(components.values()), skipped


def resolve_project(project, generate=True):
    project = pathlib.Path(project)
    notes = []
    coverage = []
    manifests = list(find_manifests(project))
    for rel in manifests:
        if rel.name in PLANNED:
            coverage.append({"path": str(rel), "status": "unidentified", "reason": PLANNED[rel.name], "type": "manifest"})
        elif rel.name == "package.json" and rel.parent != pathlib.Path("."):
            coverage.append({"path": str(rel), "status": "skipped", "reason": "nested package.json (workspace or example) is not resolved separately", "type": "manifest"})

    root_id, components = None, []
    if (project / "package.json").is_file():
        lock_path = next((project / name for name in NPM_LOCKFILES if (project / name).is_file()), None)
        if lock_path:
            lock, label, confidence = json.loads(lock_path.read_text(encoding="utf-8")), lock_path.name, "exact"
            notes.append("Versions come from the committed %s." % lock_path.name)
        elif generate:
            lock, error = generate_npm_lock(project, notes)
            label, confidence = "package-lock.json (generated)", "high"
            if lock is None:
                coverage.append({"path": "package.json", "status": "tool-missing" if "not installed" in error else "unidentified",
                                 "reason": error, "type": "manifest"})
        else:
            lock, label, confidence = None, None, None
            coverage.append({"path": "package.json", "status": "skipped", "reason": "no lockfile and --no-generate was given", "type": "manifest"})
        if lock is not None:
            root_id, components, skipped = npm_components(lock, label, confidence)
            coverage.append({"path": label, "status": "identified", "reason": "%d packages" % (len(components) - 1), "type": "lockfile"})
            for path, reason in skipped:
                coverage.append({"path": "%s#%s" % (label, path), "status": "skipped", "reason": reason, "type": "lockfile-entry"})

    if root_id is None:
        root_id = inventory.component_id("unknown", project.resolve().name, None)
        components = [{"id": root_id, "name": project.resolve().name, "ecosystem": "unknown", "version": None,
                       "scope": "runtime", "root": True, "direct": None, "depends_on": [],
                       "evidence": [{"identifier": "directory", "location": ".", "detail": "no supported manifest resolved", "confidence": "low"}]}]

    ref = None
    if (project / ".git").exists():
        out = subprocess.run(["git", "-C", str(project), "describe", "--tags", "--always", "--dirty"], capture_output=True, text=True)
        ref = out.stdout.strip() or None
    data = inventory.new_inventory("secdepth-resolve", VERSION, "source", str(project), root_id, ref=ref)
    data["components"] = components
    data["coverage"]["entries"] = coverage
    data["coverage"]["complete"] = not any(e["status"] in {"unidentified", "unpack-failed", "tool-missing"} for e in coverage)
    data["coverage"]["tools"] = [{"name": "npm", "available": shutil.which("npm") is not None}]
    data["resolution"] = notes
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("project")
    parser.add_argument("--output", help="inventory path (default: <project>/security-findings/inventory.json)")
    parser.add_argument("--no-generate", action="store_true", help="never generate a lockfile when none is committed")
    args = parser.parse_args(argv)
    project = pathlib.Path(args.project)
    if not project.is_dir():
        parser.error("%s is not a directory" % project)
    data = resolve_project(project, generate=not args.no_generate)
    problems = inventory.validate(data)
    if problems:
        print("internal error: produced an invalid inventory:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1
    out = pathlib.Path(args.output) if args.output else project / "security-findings" / "inventory.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    summary = inventory.coverage_summary(data)
    print("%s: %d components; coverage %s; complete=%s" % (out, len(data["components"]), summary, data["coverage"]["complete"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
