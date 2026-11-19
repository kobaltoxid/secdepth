# Component inventory format

The component inventory is the deterministic hand-off between tools that find components and secdepth's advisory matcher. secdepth's source resolver and binary analysis tools both write it. The authoritative definition is [inventory-schema.json](../skills/secdepth/references/inventory-schema.json); this page explains the rules a producer must follow.

## Structure

| Field | Meaning |
| --- | --- |
| `schema`, `schema_version` | Always `secdepth-inventory` and `1.0` for this version. |
| `producer` | Name and version of the tool that wrote the file. |
| `target` | `kind` is `source` or `artifact`, with the path as the caller gave it, plus a `ref` for source or a `sha256` for an artifact. |
| `root_component_id` | ID of the component that represents the target itself. |
| `components` | Every component found, with evidence. |
| `coverage` | What happened to every file the producer examined. |
| `resolution` | Notes on how versions were resolved, such as a lockfile generated on the scan date. |

## Producer rules

- Give every component at least one evidence entry. Evidence names the `identifier` that matched, the `location` inside the target, the matched `detail` and a `confidence` of `exact`, `high`, `medium` or `low`.
- Use OSV ecosystem names in `ecosystem` so the matcher can query OSV directly. Use `native` for a component without a package identity, and set `cpe` when one is known.
- Set `version` to `null` when the version is unknown. Put a candidate range in `version_range` instead of guessing a single version.
- Set `distro` for operating-system packages. The matcher then uses the distribution's own advisories, which account for backported fixes.
- Record `scope` and `direct` so readers can see why a development-only or transitive component is or is not reachable.
- List every examined file in `coverage.entries`: `identified`, `unidentified`, `unpacked` (a container whose contents were examined), `unpack-failed`, `skipped`, or `tool-missing` when an optional tool was needed but not installed. Set `coverage.complete` to `true` only when no entry is `unidentified`, `unpack-failed` or `tool-missing`; the validator rejects a complete inventory that lists any of them.

## Validate an inventory

Run the validator from the repository root:

```sh
python3 skills/secdepth/scripts/inventory.py path/to/inventory.json
```

It prints each problem and exits with status 1, or prints the component count and coverage summary when the inventory is valid.

## Related

- [Hand-off formats](handoff-formats.md)
- [Report output reference](report-output.md)
- [Use the Secdepth skill](use-secdepth.md)
