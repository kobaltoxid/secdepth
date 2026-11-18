# Secdepth

Secdepth guides an agent through advisory review and target-code analysis, then renders evidence-backed findings.

![Secdepth workflow](docs/diagrams/secdepth-flow.svg)

*The agent records sourced findings in a draft; the renderer creates the canonical JSON report and a self-contained HTML review.*

[Diagram source](docs/diagrams/secdepth-flow.d2) · [PNG preview](docs/diagrams/secdepth-flow.png)

## Install

In Codex, invoke `$skill-installer` with repository `kobaltoxid/secdepth` and skill path `skills/secdepth`. The repository is private, so installation requires GitHub access.

To install from a local clone for Codex and Claude Code:

```sh
mkdir -p ~/.local/share
gh repo clone kobaltoxid/secdepth ~/.local/share/secdepth
~/.local/share/secdepth/scripts/install-user.sh
```

Pass `codex` or `claude` to install for only one agent. Start a new agent session after installation. See the [use guide](docs/use-secdepth.md) and [report output reference](docs/report-output.md).
