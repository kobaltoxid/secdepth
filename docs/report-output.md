# Report output reference

The renderer writes a canonical `report.json` and a self-contained `report.html` review page. The JSON is authoritative; the HTML provides search, expandable findings, dependency paths, and source links.

## Finding groups and order

The renderer places findings into these sections in this order:

| Section | Condition |
| --- | --- |
| No deployable fix | Applicability is `affected`, but the update does not meet every deployable-fix condition below. |
| Fix available | Applicability is `affected`, update status is `released`, a non-empty target version other than `unknown` or `undetermined` is present, and feasibility is `feasible`. |
| No confirmed local exposure / assessment incomplete | Applicability is `not-affected`, `unknown`, or `undetermined`, or is missing. |

Within each section, findings with an SLA rank come first, ordered by ascending rank. A rank can be a number or a numeric string such as `"2"`; any other value is treated as no rank. Findings with a numeric CVSS score then sort before findings without one, with higher scores first. Equal scores use severity order, then finding ID; findings without scores use severity order, then ID.

## Files and behavior

| File | Behavior |
| --- | --- |
| `report.json` | Contains the normalized report, finding order, `ordering_policy`, and counts in `finding_groups`. |
| `report.html` | Embeds the canonical JSON, filters findings by searchable text, expands finding details, and links to valid HTTP or HTTPS sources. |

From the repository root, run `skills/secdepth/scripts/render_report.py` with a draft JSON file. From an installed skill, use its `scripts/render_report.py` path. By default, both files are written to `security-findings/` under the command's current working directory. Pass `--output-dir` to select another folder.

Before writing anything, the renderer checks the draft structure: field types, plus the `applicability`, `update_status`, and `feasibility` values that decide grouping. If a check fails, it lists every problem, exits with status 1, and writes no output. This check is not full JSON schema validation; required fields and other enums are not enforced.

When reviewing the HTML, open a finding to inspect its applicability, affected components, exploitability evidence, update recommendation, dependency path, and cited sources. An unavailable path or source record is shown as unavailable in the page.

## Related

- [Use the Secdepth skill](use-secdepth.md)
- [Report schema](../skills/secdepth/references/report-schema.json)
- [Research and evidence guidance](../skills/secdepth/references/research-guidance.md)
