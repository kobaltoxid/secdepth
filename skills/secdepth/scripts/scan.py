#!/usr/bin/env python3
"""Scan a project folder or a compiled artifact in one command, without a language model.

Usage: scan.py TARGET [--output DIR] [--fix-check] [--offline] [--osv-data DIR]

A folder runs resolve, match, check, draft and render. A file (JAR, binary, image, archive) is scanned
with secpeel first, found next to this repository or through SECPEEL_HOME. The report lands in
TARGET/security-findings for a folder, or ./security-findings for a file.
"""
import argparse
from dataclasses import dataclass
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]


@dataclass(frozen=True)
class ScanPaths:
    inventory: pathlib.Path
    matches: pathlib.Path
    checks: pathlib.Path
    draft: pathlib.Path


def secpeel_home():
    for candidate in (os.environ.get("SECPEEL_HOME"), REPO.parent / "secpeel"):
        if candidate and (pathlib.Path(candidate) / "secpeel" / "__main__.py").is_file():
            return pathlib.Path(candidate)
    return None


def step(title, cmd, cwd=None):
    print("==> " + title, flush=True)
    proc = subprocess.run(cmd, cwd=cwd)
    if proc.returncode != 0:
        sys.exit("stopped: %s failed (exit %d)" % (title, proc.returncode))


def script(name, *args):
    return [sys.executable, "-I", str(SCRIPTS / name)] + [str(a) for a in args]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="project folder or artifact file")
    parser.add_argument("--output", help="report folder (default: TARGET/security-findings or ./security-findings)")
    parser.add_argument("--fix-check", action="store_true", help="npm projects: verify upgrades by resolving them")
    parser.add_argument("--offline", action="store_true", help="use only cached advisories")
    parser.add_argument("--osv-data", help="match against downloaded OSV exports (see osvdata.py)")
    return parser, parser.parse_args(argv)


def prepare_scan(args, parser):
    target = pathlib.Path(args.target).resolve()
    if not target.exists():
        parser.error("%s does not exist" % target)
    is_artifact = target.is_file()
    out = pathlib.Path(args.output).resolve() if args.output else (
        pathlib.Path.cwd() / "security-findings" if is_artifact else target / "security-findings")
    out.mkdir(parents=True, exist_ok=True)
    paths = ScanPaths(*(out / name for name in ("inventory.json", "matches.json", "checks.json", "draft.json")))
    match_opts = (["--offline"] if args.offline else []) + (["--osv-data", args.osv_data] if args.osv_data else [])
    return target, is_artifact, out, paths, match_opts


def match_advisories(inventory, matches, match_opts):
    step("match advisories", script("match.py", inventory, "--output", matches, *match_opts))


def scan_artifact(target, out, paths, match_opts):
    home = secpeel_home()
    if home is None:
        sys.exit("secpeel not found: clone it next to secdepth or set SECPEEL_HOME")
    # One scratch folder for both secpeel steps, so evidence reuses the files the scan unpacked.
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="secdepth-unpacked-"))
    try:
        step("identify components in %s" % target.name,
             [sys.executable, "-m", "secpeel", "scan", target,
              "--output", paths.inventory, "--workdir", workdir], cwd=home)
        match_advisories(paths.inventory, paths.matches, match_opts)
        step("look for the vulnerable code",
             [sys.executable, "-m", "secpeel", "evidence", target,
              "--inventory", paths.inventory, "--matches", paths.matches,
              "--output", out / "evidence.json", "--workdir", workdir], cwd=home)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    step("check reachability", script("check.py", paths.inventory, paths.matches,
                                      "--evidence", out / "evidence.json", "--output", paths.checks))


def scan_source(target, paths, match_opts, fix_check):
    step("resolve dependencies", script("resolve.py", target, "--output", paths.inventory))
    match_advisories(paths.inventory, paths.matches, match_opts)
    step("check reachability", script("check.py", paths.inventory, paths.matches, target, "--output", paths.checks,
                                      *(["--fix-check"] if fix_check else [])))


def report(out, paths):
    step("draft the report", script("draft.py", paths.inventory, paths.matches,
                                    paths.checks, "--output", paths.draft))
    step("render the report", script("render_report.py", paths.draft, "--output-dir", out))


def print_summary(out, paths):
    report_data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    review = sum(1 for f in report_data["vulnerabilities"] if (f.get("review") or {}).get("needed"))
    coverage = json.loads(paths.inventory.read_text(encoding="utf-8"))["coverage"]
    print("\nReport: %s" % (out / "report.html"))
    for group, count in report_data["report"].get("finding_groups", {}).items():
        print("  %-55s %d" % (group, count))
    print("  %-55s %d" % ("Findings flagged for review", review))
    if not coverage.get("complete"):
        gaps = sum(1 for e in coverage["entries"] if e["status"] in ("unidentified", "unpack-failed", "tool-missing"))
        print("  Coverage is incomplete: %d gaps are listed in inventory.json" % gaps)


def main(argv=None):
    parser, args = parse_args(argv)
    target, is_artifact, out, paths, match_opts = prepare_scan(args, parser)
    if is_artifact:
        scan_artifact(target, out, paths, match_opts)
    else:
        scan_source(target, paths, match_opts, args.fix_check)
    report(out, paths)
    print_summary(out, paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
