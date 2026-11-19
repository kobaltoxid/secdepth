# Hand-off formats

secdepth and secpeel exchange three JSON files. This page lists who owns each format, which fields a reader may rely on, and the compatibility rules both projects follow.

## Files

| File | Written by | Read by | Schema (owned by the writer) |
| --- | --- | --- | --- |
| `inventory.json` | secdepth `resolve.py`, `secpeel scan` | secdepth `match.py`, `check.py`, `draft.py`; `secpeel evidence` | [inventory-schema.json](../skills/secdepth/references/inventory-schema.json) |
| `matches.json` | secdepth `match.py` | secdepth `check.py`, `draft.py`; `secpeel evidence` | [matches-schema.json](../skills/secdepth/references/matches-schema.json) |
| `evidence.json` | `secpeel evidence` | secdepth `check.py --evidence` | [evidence-schema.json](https://github.com/kobaltoxid/secpeel/blob/main/schemas/evidence-schema.json) in secpeel |

The inventory fields are explained in the [inventory format reference](inventory-format.md).

## Fields readers rely on

- From `matches.json`, `secpeel evidence` reads each advisory's `id`, `summary`, `details` and `affected[].component_id`.
- From `evidence.json`, `check.py` reads `results`, and each result's `advisory_id`, `component_id`, `proposed_reachability` and `facts`.

Every schema lists only these relied-on fields as required. Writers may add other fields at any time.

## Compatibility rules

- Each file carries `schema` and `schema_version`. A reader accepts any `1.x` version of the schemas it knows.
- A minor version may only add optional fields. The required fields keep their names, types and meaning for the whole major version.
- Renaming, removing or redefining a required field needs a new major version, and the reader must be updated before it accepts that version.
- Readers check the schema name, the major version and the required fields before using a file. A failure stops the command with the file name and the failing field or version. An empty list, such as `"results": []`, is valid.

Each reader's tests use a real file from the writer to confirm that it accepts the current format, accepts an extra optional field, and rejects an unsupported major version or a missing required field.
