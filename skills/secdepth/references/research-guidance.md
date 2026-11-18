# Research and evidence guidance

## Source order

Prefer CVE.org/NVD and the assigning CNA; the vendor or upstream project advisory and fixed release notes; then OSV, GHSA, and operating-system notices. Use exploit reports, scanners, and PoCs as supplemental sources. Capture `publisher`, `type`, `url`, `accessed_at`, and a short `supports` note. Never cite a search result page when the primary advisory is available.

## Local assessment

Identify a root service, application, image, or library and give every component a stable ID. Trace direct and transitive edges from the root through manifests and lockfiles. Inspect configuration, build and deployment workflows, image metadata, and call sites or entry points. For every finding record:

- `presence`: present, absent, unknown, or undetermined;
- `reachability`: reachable, not-reachable, conditional, or unknown;
- preconditions an attacker would need;
- concrete local evidence (file and line, command output, or image digest);
- confidence: high, medium, low, or unknown.

Do not turn a vulnerable version range into a claim that the vulnerable code path is reachable. If repository context was not supplied, say that explicitly and use `undetermined`.

## Fix and SLA semantics

Use the top-level `update_status` values `released`, `planned`, `mitigation-only`, `no-fix`, or `unknown`; do not use the older nested status name. A mitigation is not a deployable fix. `recommended_target_version` should be an exact fixed version when the source supports it, otherwise `unknown`. `patch_eta` must contain `certainty` (`confirmed`, `estimated`, or `unknown`) and source IDs. A finding is `Fix available` only when applicability is `affected`, status is `released`, target version is present, and feasibility is exactly `feasible`. Put all other affected findings in `No deployable fix`; put `not-affected`, `unknown`, and `undetermined` in the lower assessment-incomplete group.

SLA is optional. When present, `sla.priority_rank` is a numeric rank where 1 is most urgent, with due date and source. Within each group, findings with a rank come first, ordered by ascending rank. Then sort by numeric CVSS score descending, severity label (`critical`, `high`, `medium`, `low`, `none`) for equal or missing scores, and CVE ID ascending.

## Recommendations

State the fixed release and rollout recommendation, compatibility or migration checks, temporary compensating controls, and a recheck date. If a fix cannot be deployed, explain the blocker and the residual risk. Keep facts, estimates, and analyst inferences in separate fields.
