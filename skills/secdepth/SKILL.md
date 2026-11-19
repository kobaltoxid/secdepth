---
name: secdepth
description: Research a named CVE or security issue, or scan a project's full dependency tree for every published vulnerability, then assess exploitability in the codebase and produce linked, SLA-ordered JSON and offline HTML findings. Use for one-off vulnerability investigations; do not use as a continuous scanner or to run exploits.
---

# Secdepth

Produce a defensible, source-linked investigation of a target project's security exposure. This is a search and analysis workflow, not a daemon. Do not exploit systems or edit the target repository.

Deterministic scripts do the detection: resolving dependencies, matching advisories, collecting reachability evidence and drafting the report. Your job is to run them, review what they flag, and explain the result. Do not rebuild findings by hand that the scripts already produce, and do not change a verdict without citing new evidence.

## Modes

Choose the mode from the invocation and start immediately. Do not ask the caller to pick a mode, a scan depth, or which advisories to include.

- **Named issue**: the caller supplies a CVE, GHSA, OSV, or other advisory ID, an incident, a package, an image, or a product. Investigate that issue against the target even if scanners and advisory databases do not list it as affecting the project; a caller often names an issue precisely because a tool missed it.
- **Project scan**: the caller supplies no issue. Find every published vulnerability that affects the target: advisories for the project itself when it is a published package, and advisories for every component in its resolved dependency tree, direct and transitive, across every ecosystem present. Include development, build, and optional dependencies; record their scope instead of dropping them. Run the [deterministic pipeline](#deterministic-pipeline), then [review](#review) what it flags. Follow [Project scan](references/research-guidance.md#project-scan) for coverage rules and for ecosystems the scripts do not support yet.

Record the mode and scan coverage in `report.target`. If an input is missing or ambiguous, choose the broader reasonable reading, record the assumption in the report, and continue.

## Output

Unless the caller gives an output directory, create `<caller's current working directory>/security-findings/` before researching and keep the draft JSON, canonical `report.json`, and generated `report.html` there. Do not leave a draft report in the skill directory or elsewhere. Use `scripts/render_report.py` from this skill to normalize a report and render an offline, searchable, expandable HTML view:

```sh
python3 <skill-dir>/scripts/render_report.py ./security-findings/draft.json
python3 <skill-dir>/scripts/render_report.py ./audit/security-findings/draft.json --output-dir ./audit/security-findings
```

`<skill-dir>` is the directory that contains this `SKILL.md`.

The JSON is authoritative. HTML must remain usable without a network connection and must link to every cited source. The report schema and ordering rules are in [references/report-schema.json](references/report-schema.json) and [references/research-guidance.md](references/research-guidance.md).

## Deterministic pipeline

Run these from the target project's root. Each writes into `security-findings/` and needs only Python 3; `resolve.py` and `--fix-check` also use npm when the project has no lockfile.

```sh
python3 <skill-dir>/scripts/resolve.py .                         # inventory.json: full dependency tree and coverage
python3 <skill-dir>/scripts/match.py security-findings/inventory.json        # matches.json: advisories per component
python3 <skill-dir>/scripts/check.py security-findings/inventory.json security-findings/matches.json . --fix-check   # checks.json
python3 <skill-dir>/scripts/draft.py security-findings/inventory.json security-findings/matches.json security-findings/checks.json
python3 <skill-dir>/scripts/render_report.py security-findings/draft.json
```

- `resolve.py` lists manifests it cannot resolve yet in the inventory's coverage ledger. Report those gaps; do not treat a partial inventory as a clean scan. The format is described in [references/inventory-schema.json](references/inventory-schema.json).
- `match.py` caches advisories in `~/.cache/secdepth`. Use `--offline` when the network is unavailable and say so in the summary.
- `check.py` proposes `not-reachable` or `conditional` for every advisory and component. It never claims `reachable` on its own.
- `draft.py` marks findings that need your review with `review.needed`.

If a step fails, report the error and the step; do not replace the step with manual research unless the caller asks.

## Review

Review only what the pipeline flags: findings with `review.needed` (conditional reachability or matcher notes), plus the coverage gaps and lookups that were not queried. For each flagged finding:

1. Read the cited call sites and the code around them. Decide whether attacker-controlled input can reach the vulnerable function under default configuration, under a common configuration, or not at all.
2. Set `exploitability.reachability` to `reachable`, `conditional` or `not-reachable`, fill `attack_preconditions`, and add the file and line you relied on to `evidence`. Raise or lower `confidence` to match.
3. Add `temporary_mitigations` and `blockers` when the code or the advisory supports them. A mitigation is never a patch.
4. For a matcher note, such as several CVE IDs grouped as aliases, check the primary advisories and either keep the group or split it into separate findings with their own sources.
5. Clear `review.needed` once the finding is reviewed.

Do not change scope, versions, ranges, CVSS data or fix-check results; they come from the data sources. Re-run `render_report.py` after editing `draft.json`.

## Named issue

Run the pipeline first. If the named ID appears in `matches.json`, review that finding as above. If it does not, research it from primary sources (CVE.org or NVD, the assigning CNA, the project's advisory and release notes, then OSV, GHSA and distribution notices), decide which components and versions it affects, and add one finding to `draft.json` with cited sources and local evidence. Say explicitly that no database matched it.

## Reporting rules

Assign an SLA rank or due date only when supplied by the caller or an authoritative policy source. The renderer groups findings into `No deployable fix`, `Fix available` and `No confirmed local exposure / assessment incomplete`; the rules are in [references/research-guidance.md](references/research-guidance.md). Return the output paths and a short decision summary: what is reachable, what to upgrade first, and what could not be checked. Do not silently fill unknown facts.

## Portable use

The skill uses ordinary Markdown, JSON, and Python 3 standard library so it can be copied into Codex, Claude-compatible skill directories, a local agent bundle, or another repository. `agents/openai.yaml` is optional Codex UI metadata; other agents can use `SKILL.md` directly.
