# Secdepth

Secdepth is an agent skill for investigating CVEs and other code security issues. It helps you determine whether a project is affected, trace the dependency involved, and check whether a fix can be deployed.

## Install

In Codex, invoke `$skill-installer` with repository `kobaltoxid/secdepth` and skill path `skills/secdepth`. The repository is private, so installation requires GitHub access.

To install from a local clone for Codex and Claude Code:

```sh
mkdir -p ~/.local/share
gh repo clone kobaltoxid/secdepth ~/.local/share/secdepth
~/.local/share/secdepth/scripts/install-user.sh
```

Pass `codex` or `claude` to install for only one agent. Start a new agent session after installation. Report rendering requires Python 3.

## Use it in a project

From the project root, invoke `$secdepth` with the CVE or issue you want to investigate. Include your remediation deadlines or priority rules if they should guide the report. The agent checks primary advisories against the project's dependencies, configuration, and code. See the [use guide](docs/use-secdepth.md).

![An analyst supplies an issue to Secdepth, which produces JSON and HTML reports.](docs/diagrams/secdepth-flow.svg)

Figure 1. The agent drafts findings with citations, then the renderer writes both reports. [D2 source](docs/diagrams/secdepth-flow.d2)

By default, the reports go in `security-findings/`. Use `report.json` as the authoritative record and open `report.html` to search findings, inspect dependency paths, and follow source links. See the [report output reference](docs/report-output.md).
