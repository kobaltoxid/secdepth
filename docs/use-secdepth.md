# Use the Secdepth Skill

Use this procedure to scan a project for published vulnerabilities, or to investigate one named issue, and review the linked findings. The skill guides an agent to check current advisories, map affected dependencies, and assess whether vulnerable code is reachable in the target.

## Prerequisites

- An AI agent that can read the target project and access current security advisories.
- Python 3 to render the final report.
- Optionally, a CVE, advisory ID, incident, package, image, or product to investigate. Without one, the skill scans the whole project.

## Steps

1. Start the agent from the target project's root and invoke the skill: `$secdepth` in Codex or `/secdepth` in Claude Code. Invoke it alone to scan every dependency, or add an issue identifier to check that issue only. Add any known SLA policy and an optional report destination. The skill does not ask which mode or dependency depth to use.
2. Let the agent run the deterministic pipeline. It writes each stage to `security-findings/` in its current working directory:

   ```sh
   python3 skills/secdepth/scripts/resolve.py .
   python3 skills/secdepth/scripts/match.py security-findings/inventory.json
   python3 skills/secdepth/scripts/check.py security-findings/inventory.json security-findings/matches.json . --fix-check
   python3 skills/secdepth/scripts/draft.py security-findings/inventory.json security-findings/matches.json security-findings/checks.json
   python3 skills/secdepth/scripts/render_report.py security-findings/draft.json
   ```

   From an installed skill, use its `scripts/` path instead. A scan covers direct, transitive, development, and build dependencies. When a lockfile is missing, `resolve.py` resolves one in a temporary copy so the target stays unchanged. You can run these commands yourself without an agent.
3. Let the agent review the findings marked for review, mostly those with conditional reachability. It reads the cited call sites, sets the final verdict with evidence, and renders the report again.
4. Review the authoritative `report.json` and the searchable `report.html`. The HTML shows affected findings without a deployable fix first, affected findings with a feasible released fix next, and findings with no confirmed local exposure or incomplete assessment last.

## Verify

Confirm that the renderer produced `report.json` and `report.html` in the requested folder. Open the HTML, search for a CVE or component, follow its source links, and check the dependency path from the root application to the affected component. Review grouping and ordering rules in the [report output reference](report-output.md).

## Related

- [Skill workflow](../skills/secdepth/SKILL.md)
- [Report schema](../skills/secdepth/references/report-schema.json)
- [Research and evidence guidance](../skills/secdepth/references/research-guidance.md)
- [Report output reference](report-output.md)
- [Project README](../README.md)
