---
name: secdepth
description: Research code-related security incidents and CVEs, assess exploitability in a target codebase, and produce linked, SLA-ordered JSON and offline HTML findings. Use for vulnerability investigations; do not use as a continuous scanner or to run exploits.
---

# Secdepth

Produce a defensible, source-linked investigation for a named CVE, incident, package, image, or affected product. This is a search and analysis workflow, not a daemon. Do not exploit systems or edit the target repository.

## Output

Unless the caller gives an output directory, create `<caller's current working directory>/security-findings/` before researching and keep the draft JSON, canonical `report.json`, and generated `report.html` there. Do not leave a draft report in the skill directory or elsewhere. Use `scripts/render_report.py` from this skill to normalize a report and render an offline, searchable, expandable HTML view:

```sh
python3 /path/to/secdepth/scripts/render_report.py ./security-findings/draft.json
python3 /path/to/secdepth/scripts/render_report.py ./audit/security-findings/draft.json --output-dir ./audit/security-findings
```

The JSON is authoritative. HTML must remain usable without a network connection and must link to every cited source. The report schema and ordering rules are in [references/report-schema.json](references/report-schema.json) and [references/research-guidance.md](references/research-guidance.md).

## Research workflow

1. Establish scope: current UTC date/time, target repository or runtime, commit/branch, manifests and lockfiles, container/base image, deployment configuration, and the exact issue identifiers. If no local context is available, set local exploitability to `undetermined` and say why.
2. Start with primary sources: CVE.org/NVD, the assigning CNA, vendor or project advisory and release notes, then OSV/GHSA and distribution notices. Use exploit writeups or PoCs only as supplemental evidence. Record publisher, source type, URL, access date, and which claim it supports.
3. Describe each CVE in plain language: affected product/package and ranges, attack vector and preconditions, impact, CVSS score/vector and severity, CWE when available, disclosure and update dates, and whether exploitation is known. Keep confirmed patch dates separate from estimated ETA; use `unknown` when no ETA is published.
4. Inspect the target without changing it. Trace the root service/application/container through manifests, lockfiles, image metadata, build/workflow files, configuration, and code usage. Record stable component IDs, direct versus transitive status, exact dependency paths, reachable entry points, and evidence. A version match alone does not prove exploitability.
5. Assess in-us exploitability with `presence`, `reachability`, `attack_preconditions`, `evidence`, and `confidence`. State what is not known. Recommend a target fixed version or vendor update when released, describe temporary mitigations, and record blockers such as incompatible APIs, unavailable builds, unsupported platforms, or an unfixable upstream.
6. Assign an SLA rank or due date only when supplied by the caller or an authoritative policy source. A finding belongs in `Fix available` only when applicability is `affected`, update status is `released`, target version is non-empty and not `unknown` or `undetermined`, and feasibility is `feasible`. Put all other affected findings in `No deployable fix`. Put `not-affected`, `unknown`, and `undetermined` applicability in `No confirmed local exposure / assessment incomplete`. Within each group, ranked findings come first by ascending rank. Then order by numeric CVSS score descending, severity label for equal or missing scores, and CVE ID ascending.
7. Run the renderer against `security-findings/draft.json`, inspect both files, and return the output paths plus a short decision summary. Do not silently fill unknown facts or claim that a mitigation is a patch.

## Portable use

The skill uses ordinary Markdown, JSON, and Python 3 standard library so it can be copied into Codex, Claude-compatible skill directories, a local agent bundle, or another repository. `agents/openai.yaml` is optional Codex UI metadata; other agents can use `SKILL.md` directly.
