#!/usr/bin/env python3
"""Scan a project folder or a compiled artifact in one command, without a language model.

Usage: scan.py TARGET [--output DIR] [--fix-check] [--offline] [--osv-data DIR]

A folder runs resolve, match, check, draft and render. A file (JAR, binary, image, archive) is scanned
with secpeel first, found next to this repository or through SECPEEL_HOME. The report lands in
TARGET/security-findings for a folder, or ./security-findings for a file.
"""
import argparse
import json
import os
import pathlib
import subprocess
import sys

SCRIPTS = pathlib.Path(__file__).resolve().parent
REPO = SCRIPTS.parents[2]


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="project folder or artifact file")
    parser.add_argument("--output", help="report folder (default: TARGET/security-findings or ./security-findings)")
    parser.add_argument("--fix-check", action="store_true", help="npm projects: verify upgrades by resolving them")
    parser.add_argument("--offline", action="store_true", help="use only cached advisories")
    parser.add_argument("--osv-data", help="match against downloaded OSV exports (see osvdata.py)")
    args = parser.parse_args(argv)

    target = pathlib.Path(args.target).resolve()
    if not target.exists():
        parser.error("%s does not exist" % target)
    is_artifact = target.is_file()
    out = pathlib.Path(args.output).resolve() if args.output else (
        pathlib.Path.cwd() / "security-findings" if is_artifact else target / "security-findings")
    out.mkdir(parents=True, exist_ok=True)
    inventory, matches, checks, draft = (out / n for n in ("inventory.json", "matches.json", "checks.json", "draft.json"))
    match_opts = (["--offline"] if args.offline else []) + (["--osv-data", args.osv_data] if args.osv_data else [])

    if is_artifact:
        home = secpeel_home()
        if home is None:
            sys.exit("secpeel not found: clone it next to secdepth or set SECPEEL_HOME")
        step("identify components in %s" % target.name,
             [sys.executable, "-m", "secpeel", "scan", target, "--output", inventory], cwd=home)
        step("match advisories", script("match.py", inventory, "--output", matches, *match_opts))
        step("look for the vulnerable code",
             [sys.executable, "-m", "secpeel", "evidence", target, "--inventory", inventory, "--matches", matches,
              "--output", out / "evidence.json"], cwd=home)
        step("check reachability", script("check.py", inventory, matches, "--evidence", out / "evidence.json", "--output", checks))
    else:
        step("resolve dependencies", script("resolve.py", target, "--output", inventory))
        step("match advisories", script("match.py", inventory, "--output", matches, *match_opts))
        step("check reachability", script("check.py", inventory, matches, target, "--output", checks,
                                          *(["--fix-check"] if args.fix_check else [])))
    step("draft the report", script("draft.py", inventory, matches, checks, "--output", draft))
    step("render the report", script("render_report.py", draft, "--output-dir", out))

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    review = sum(1 for f in report["vulnerabilities"] if (f.get("review") or {}).get("needed"))
    coverage = json.loads(inventory.read_text(encoding="utf-8"))["coverage"]
    print("\nReport: %s" % (out / "report.html"))
    for group, count in report["report"].get("finding_groups", {}).items():
        print("  %-55s %d" % (group, count))
    print("  %-55s %d" % ("Findings flagged for review", review))
    if not coverage.get("complete"):
        gaps = sum(1 for e in coverage["entries"] if e["status"] in ("unidentified", "unpack-failed", "tool-missing"))
        print("  Coverage is incomplete: %d gaps are listed in inventory.json" % gaps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
