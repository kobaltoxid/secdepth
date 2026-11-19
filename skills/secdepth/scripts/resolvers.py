"""Deterministic lockfile parsers for ecosystems other than npm.

Each parser returns a Resolution: packages with their dependency names, the root's direct runtime and
development dependencies, notes, and coverage gaps. `graph_components` turns that into inventory
components with dependency edges and propagated scope.
"""
import collections
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET

import inventory

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None


class Resolution:
    def __init__(self, ecosystem, manifest, root_name=None, root_version=None, confidence="exact"):
        self.ecosystem = ecosystem
        self.manifest = manifest
        self.root_name = root_name
        self.root_version = root_version
        self.confidence = confidence
        self.packages = []      # dicts: name, version, deps (list of (name, version-or-None)), dev (bool or None), purl
        self.direct_runtime = set()
        self.direct_dev = set()
        self.notes = []
        self.gaps = []          # coverage entries for things that could not be resolved

    def add(self, name, version, deps=(), dev=None, purl=None):
        self.packages.append({"name": name, "version": version, "deps": list(deps), "dev": dev, "purl": purl})


def pypi_name(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def _purl(kind, name, version):
    return "pkg:%s/%s@%s" % (kind, urllib.parse.quote(name, safe="/"), urllib.parse.quote(version, safe=""))


def _toml(path):
    if tomllib is None:
        raise RuntimeError("TOML lockfiles need Python 3.11 or newer")
    with open(path, "rb") as fh:
        return tomllib.load(fh)


# --- Rust ---------------------------------------------------------------------------------------

def cargo(project):
    lock = _toml(project / "Cargo.lock")
    res = Resolution("crates.io", "Cargo.lock")
    manifest = _toml(project / "Cargo.toml") if (project / "Cargo.toml").is_file() else {}
    dev_names = set(manifest.get("dev-dependencies", {})) | set(manifest.get("build-dependencies", {}))
    members = []
    for pkg in lock.get("package", []):
        deps = []
        for dep in pkg.get("dependencies", []):
            parts = dep.split()
            deps.append((parts[0], parts[1] if len(parts) > 1 else None))
        source = pkg.get("source")
        if source is None:
            members.append((pkg["name"], pkg["version"], deps))
        elif source.startswith("registry+") and "crates.io-index" in source or source.startswith("sparse+https://index.crates.io"):
            res.add(pkg["name"], pkg["version"], deps, purl=_purl("cargo", pkg["name"], pkg["version"]))
        else:
            res.gaps.append({"path": "Cargo.lock#%s" % pkg["name"], "status": "unidentified",
                             "reason": "non-crates.io source %s is not matched against advisories" % source.split("+")[0],
                             "type": "lockfile-entry"})
    if members:
        root = next((m for m in members if m[0] == manifest.get("package", {}).get("name")), members[0])
        res.root_name, res.root_version = root[0], root[1]
        for name, _version, deps in members:
            for dep, _ in deps:
                (res.direct_dev if dep in dev_names else res.direct_runtime).add(dep)
        res.direct_runtime -= {m[0] for m in members}
        res.direct_dev -= {m[0] for m in members} | res.direct_runtime
    return res


# --- Python ----------------------------------------------------------------------------------------

def poetry(project):
    lock = _toml(project / "poetry.lock")
    pyproject = _toml(project / "pyproject.toml") if (project / "pyproject.toml").is_file() else {}
    tool = pyproject.get("tool", {}).get("poetry", {})
    res = Resolution("PyPI", "poetry.lock", tool.get("name") or pyproject.get("project", {}).get("name"),
                     tool.get("version") or pyproject.get("project", {}).get("version"))
    for pkg in lock.get("package", []):
        deps = [(pypi_name(d), None) for d in (pkg.get("dependencies") or {})]
        dev = {"dev": True, "main": False}.get(pkg.get("category"))
        name = pypi_name(pkg["name"])
        res.add(name, pkg["version"], deps, dev, _purl("pypi", name, pkg["version"]))
    res.direct_runtime = {pypi_name(d) for d in tool.get("dependencies", {}) if d.lower() != "python"}
    res.direct_runtime |= {pypi_name(re.split(r"[ <>=!~;\[]", d, maxsplit=1)[0])
                           for d in pyproject.get("project", {}).get("dependencies", [])}
    dev = set(tool.get("dev-dependencies", {}))
    for group in tool.get("group", {}).values():
        dev |= set(group.get("dependencies", {}))
    res.direct_dev = {pypi_name(d) for d in dev} - res.direct_runtime
    return res


def uv(project):
    lock = _toml(project / "uv.lock")
    res = Resolution("PyPI", "uv.lock")
    for pkg in lock.get("package", []):
        source = pkg.get("source", {})
        name = pypi_name(pkg["name"])
        deps = [(pypi_name(d["name"]), d.get("version")) for d in pkg.get("dependencies", [])]
        if "editable" in source or "virtual" in source:
            res.root_name, res.root_version = name, pkg.get("version")
            res.direct_runtime |= {d for d, _ in deps}
            for group in (pkg.get("dev-dependencies") or {}).values():
                res.direct_dev |= {pypi_name(d["name"]) for d in group}
            continue
        if "registry" not in source:
            res.gaps.append({"path": "uv.lock#%s" % name, "status": "unidentified",
                             "reason": "non-registry source is not matched against advisories", "type": "lockfile-entry"})
            continue
        res.add(name, pkg["version"], deps, purl=_purl("pypi", name, pkg["version"]))
    res.direct_dev -= res.direct_runtime
    return res


def requirements(project, filename="requirements.txt"):
    res = Resolution("PyPI", filename)
    for number, raw in enumerate((project / filename).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            if line:
                res.gaps.append({"path": "%s:%d" % (filename, number), "status": "unidentified",
                                 "reason": "option %r is not followed" % line.split()[0], "type": "requirement"})
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;,]+)", line)
        if m:
            name = pypi_name(m.group(1))
            res.add(name, m.group(2), purl=_purl("pypi", name, m.group(2)))
            res.direct_runtime.add(name)
        else:
            res.gaps.append({"path": "%s:%d" % (filename, number), "status": "unidentified",
                             "reason": "requirement %r is not pinned with ==, so its version is unknown" % line,
                             "type": "requirement"})
    res.notes.append("%s lists only what it pins; transitive dependencies are covered only if the file is fully "
                     "pinned (for example pip-compile output)." % filename)
    return res


# --- Go ----------------------------------------------------------------------------------------------

def gomod(project):
    text = (project / "go.mod").read_text(encoding="utf-8", errors="replace")
    module = re.search(r"^module\s+(\S+)", text, re.M)
    res = Resolution("Go", "go.mod", module.group(1) if module else None, None)
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        entry = line[len("require "):] if line.startswith("require ") and not line.endswith("(") else (line if in_block else None)
        if not entry or entry.startswith("//"):
            continue
        parts = entry.split()
        if len(parts) >= 2:
            name, version = parts[0], parts[1].lstrip("v")
            res.add(name, version, purl=_purl("golang", name, parts[1]))
            if "// indirect" not in entry:
                res.direct_runtime.add(name)
    toolchain = re.search(r"^toolchain\s+go(\S+)", text, re.M)
    if toolchain:
        res.add("stdlib", toolchain.group(1), purl=_purl("golang", "stdlib", toolchain.group(1)))
        res.direct_runtime.add("stdlib")
    if re.search(r"^replace\s", text, re.M):
        res.notes.append("go.mod has replace directives; replaced modules are reported under their original path.")
    res.notes.append("go.mod lists every module in the build graph (Go 1.17+); edges between modules are not recorded, "
                     "and test-only modules are not separated.")
    return res


# --- .NET ----------------------------------------------------------------------------------------------

def nuget(project):
    data = json.loads((project / "packages.lock.json").read_text(encoding="utf-8"))
    res = Resolution("NuGet", "packages.lock.json")
    seen = {}
    for framework, entries in (data.get("dependencies") or {}).items():
        for name, info in entries.items():
            if info.get("type") == "Project" or not info.get("resolved"):
                continue
            key = (name, info["resolved"])
            if key not in seen:
                seen[key] = True
                res.add(name, info["resolved"], [(d, None) for d in info.get("dependencies") or {}],
                        purl=_purl("nuget", name, info["resolved"]))
            if info.get("type") == "Direct":  # CentralTransitive pins are still transitive
                res.direct_runtime.add(name)
    return res


# --- Java ---------------------------------------------------------------------------------------------

def gradle_lock(project):
    res = Resolution("Maven", "gradle.lockfile")
    for raw in (project / "gradle.lockfile").read_text(encoding="utf-8").splitlines():
        if raw.startswith("#") or "=" not in raw or raw.startswith("empty="):
            continue
        coords, configs = raw.split("=", 1)
        parts = coords.split(":")
        if len(parts) != 3:
            continue
        name, version = "%s:%s" % (parts[0], parts[1]), parts[2]
        only_test = all(c.startswith("test") for c in configs.split(","))
        res.add(name, version, dev=only_test, purl="pkg:maven/%s/%s@%s" % (parts[0], parts[1], version))
    res.notes.append("gradle.lockfile has no dependency graph; every locked module is attached to the root.")
    return res


def pom(project):
    tree = ET.parse(project / "pom.xml")
    ns = {"m": tree.getroot().tag.split("}")[0].strip("{")} if tree.getroot().tag.startswith("{") else {}
    q = (lambda tag: "m:" + tag) if ns else (lambda tag: tag)
    root = tree.getroot()
    props = {}
    for prop in root.findall(q("properties") + "/*", ns):
        props[prop.tag.split("}")[-1]] = (prop.text or "").strip()
    props["project.version"] = (root.findtext(q("version"), namespaces=ns) or "").strip()

    def expand(value):
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), value or "").strip()

    res = Resolution("Maven", "pom.xml", "%s:%s" % (expand(root.findtext(q("groupId"), namespaces=ns)),
                                                   expand(root.findtext(q("artifactId"), namespaces=ns))),
                     props["project.version"] or None, confidence="high")
    for dep in root.findall(q("dependencies") + "/" + q("dependency"), ns):
        group, artifact = expand(dep.findtext(q("groupId"), namespaces=ns)), expand(dep.findtext(q("artifactId"), namespaces=ns))
        version, scope = expand(dep.findtext(q("version"), namespaces=ns)), expand(dep.findtext(q("scope"), namespaces=ns))
        name = "%s:%s" % (group, artifact)
        if not version or "${" in version:
            res.gaps.append({"path": "pom.xml#%s" % name, "status": "unidentified",
                             "reason": "version is managed elsewhere (parent or BOM) and was not resolved", "type": "manifest-entry"})
            continue
        res.add(name, version, dev=scope == "test", purl="pkg:maven/%s/%s@%s" % (group, artifact, version))
        (res.direct_dev if scope == "test" else res.direct_runtime).add(name)
    res.gaps.append({"path": "pom.xml#transitive", "status": "unidentified",
                     "reason": "transitive Maven dependencies need Maven to resolve; only direct dependencies are listed",
                     "type": "manifest"})
    return res


# --- shared -----------------------------------------------------------------------------------------

def graph_components(res, root_id, location_prefix=None):
    """Build components with edges; scope is runtime when reachable from a runtime direct dependency."""
    by_name = collections.defaultdict(list)
    for pkg in res.packages:
        by_name[pkg["name"]].append(pkg)

    def ids_for(name, version=None):
        candidates = by_name.get(name, [])
        if version:
            candidates = [p for p in candidates if p["version"] == version] or candidates
        return [inventory.component_id(res.ecosystem, p["name"], p["version"]) for p in candidates[:1]]

    components = {}
    for pkg in res.packages:
        cid = inventory.component_id(res.ecosystem, pkg["name"], pkg["version"])
        comp = components.setdefault(cid, {
            "id": cid, "name": pkg["name"], "ecosystem": res.ecosystem, "version": pkg["version"], "purl": pkg["purl"],
            "scope": "unknown", "direct": pkg["name"] in res.direct_runtime or pkg["name"] in res.direct_dev,
            "root": False, "manifest": res.manifest, "depends_on": [],
            "evidence": [{"identifier": res.manifest, "location": (location_prefix or res.manifest), "detail": pkg["version"],
                          "confidence": res.confidence}],
        })
        for dep, version in pkg["deps"]:
            for target in ids_for(dep, version):
                if target != cid and target not in comp["depends_on"]:
                    comp["depends_on"].append(target)
        if pkg["dev"] is True:
            comp["scope"] = "dev"
        elif pkg["dev"] is False:
            comp["scope"] = "runtime"

    def reach(names):
        seen, queue = set(), collections.deque(t for n in names for t in ids_for(n))
        while queue:
            cid = queue.popleft()
            if cid in seen or cid not in components:
                continue
            seen.add(cid)
            queue.extend(components[cid]["depends_on"])
        return seen

    has_directs = bool(res.direct_runtime or res.direct_dev)
    runtime, dev = reach(res.direct_runtime), reach(res.direct_dev)
    for cid, comp in components.items():
        if comp["scope"] != "unknown":
            continue
        if cid in runtime or not has_directs:
            comp["scope"] = "runtime"
        elif cid in dev:
            comp["scope"] = "dev"
    root_deps = sorted({t for n in res.direct_runtime | res.direct_dev for t in ids_for(n)}) if has_directs \
        else sorted(components)
    for comp in components.values():
        comp["depends_on"].sort()
    return list(components.values()), root_deps


RESOLVERS = [
    ("Cargo.lock", cargo),
    ("poetry.lock", poetry),
    ("uv.lock", uv),
    ("requirements.txt", requirements),
    ("go.mod", gomod),
    ("packages.lock.json", nuget),
    ("gradle.lockfile", gradle_lock),
    ("pom.xml", pom),
]
