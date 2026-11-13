# Configuration and stages

Start from [`examples/lab.json`](../examples/lab.json), not a target-specific recipe. All shipped target URLs are loopback-only. For any non-lab use, obtain explicit permission covering the endpoint, tables, request budget, time window, and handling of returned data.

## Lab configuration

| Key | Meaning in the shipped example |
| --- | --- |
| `target.base_url` | GET URL ending in `id=`; the engine appends an encoded payload. |
| `target.schema` | `boolrace_lab`, the fixture's database. For extraction/verification, a configured schema must exactly equal the connection's `DATABASE()` result; cross-schema extraction is unsupported. |
| `target.verify_tls` | `true`. The lab uses plain HTTP on loopback; do not disable certificate validation for remote HTTPS endpoints. |
| `injection.prefix` / `suffix` | `-1 ` and `-- -`, matched to the deliberately vulnerable numeric fixture query. |
| `injection.union_template` | Five-column reflected `UNION ALL` shape, matching the fixture's binary projections; see database constraints in [limitations](limitations.md). |
| `slots.definitions` / `probe_order` | One title plus four paragraph slots; definitions and ordering are explicit. |
| `extraction.mode` | `compress` in the example; the smoke runner also accepts `union`. |
| `extraction.framing` | `length`, recommended to preserve separators embedded inside values. |
| `extraction.row_sep` | Unit separator, represented as `\u001f` in JSON. |
| `extraction.null_marker` | An explicit sentinel. A real value equal to that sentinel is ambiguous; see limitations. |
| `extraction.chunk` | 1,024 characters per requested chunk; channel capacity and server limits still matter. |
| `extraction.workers` / `throttle` | One worker and a small delay; avoid aggressive concurrency against shared systems. |
| `tables` | Only `specimens`, with an explicit ordered column projection. |
| `output.dir` | `./boolrace_out/lab`, ignored by Git. |

The connection's default database in this lab is `boolrace_lab`. Setting `target.schema` does not change the application's database connection: extraction and verification reject a selected schema that differs from `DATABASE()`. Without explicit tables, discovery must resolve to exactly one schema. This is not a privilege boundary; keep the database account and grants scoped to the fixture.

Table identifiers must fully match the ASCII pattern `[A-Za-z0-9_][A-Za-z0-9_-]*`; paths, dots, spaces, and Unicode identifiers are rejected rather than normalized. The case-insensitive reserved names are `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `_PROBE`, `_FINGERPRINT`, `_SCHEMA`, and `_VERIFY`. Table names must also be unique case-insensitively. Each table requires a nonempty column list whose identifiers fully match `[A-Za-z0-9_]+`, with no case-insensitive duplicates. Do not supply SQL fragments or untrusted configurations.

## Stages

- `probe`: makes requests to discover the column/slot shape and estimate carrying capacity. A visible short marker does not prove large-response fidelity.
- `fingerprint`: makes database capability/environment queries; it can expose database and account metadata. Not needed by the minimal smoke path.
- `enumerate`: metadata enumeration. Not used in the lab walkthrough or smoke runner.
- `extract`: extracts the explicit configured table projection. `--table specimens` selects the lab table.
- `verify`: reads saved extracted rows and queries the server for comparison. Inspect `_verify.json`, not just the exit message.
- `report`: unsupported in v0.1.0; exits with status 2, including with `--dry-run`. It does not generate a Markdown/JSON report. Existing stage JSON artifacts remain available. The lab runner calls only `extract` and `verify`, then independently writes `lab-report.json` after exact-row and CRC checks pass.
- `all`: orchestrates stages; it is intentionally not used in this walkthrough. Prefer explicit stages and tables when controlling scope.

`--out` selects the output location. `--config` should point to a real JSON configuration. Keep a separate directory for each experiment; files from a previous run are not evidence for a later one.

## Dry-run contract

```sh
python boolrace.py extract --config examples/lab.json --dry-run
```

For v0.1.0 this is a **network-free, output-write-free plan**. It can validate locally known configuration and describe intended stages and tables. It cannot know runtime slot capacities, table sizes, server capabilities, or dynamically generated queries without talking to a server. It is not a complete SQL transcript, a safe-to-run certification, or a performance estimate.

## Modes and scope

`union` places a row aggregate into a reflected slot; `compress` transports a compressed/base64 aggregate in chunks. Other experimental paths, where present in the engine, are not validated merely by these two smoke runs. Length framing is recommended, but it does not create deterministic ordering or a transaction snapshot.

`column` is disabled in v0.1.0. Do not use historical examples recommending it: equal column lengths do not prove that values at the same position belong to the same row.
