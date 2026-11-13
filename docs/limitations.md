# Known limits and integrity model

v0.1.0 is experimental research code. The local fixture checks a narrow, static case; it does not establish general correctness across MySQL/MariaDB versions, frameworks, response transforms, data types, or changing databases.

## What verification means

A server/local sum of per-row CRC32 values is a useful corruption signal. It is **not cryptographic**, order-sensitive, collision-free, or independent of the configured serialization. Matching CRC sums cannot authenticate a server, prove every row is unique, establish a transaction snapshot, or rule out all substitutions. A failed, absent, or unknown verification result must not be treated as success.

The lab adds a stronger fixture-specific check: exact comparison of the returned row multiset and an independently authored expected-data manifest, including the row count. This only proves those particular synthetic values under that run's conditions.

## Disabled column mode

Independent column aggregates can return values in different orders. Equal array lengths do not establish cross-column row identity. Multiple requests can also see different database states. `column` therefore fails closed in v0.1.0 pending an explicit stable-key alignment and snapshot/consistency design. Do not restore it merely because a benchmark appears faster.

## Native reporting and identifier limits

Native `report` is unsupported in v0.1.0 and exits with status 2, even with `--dry-run`. Stage JSON artifacts remain available; there is no generated native Markdown/JSON report. The smoke runner's separate `lab-report.json` summarizes only its successful exact-row and CRC checks.

Extraction and verification require a selected schema to exactly equal the connection's `DATABASE()` result; cross-schema extraction is unsupported. Table names are restricted to ASCII `[A-Za-z0-9_][A-Za-z0-9_-]*`, and column names to ASCII `[A-Za-z0-9_]+`. Reserved table filenames and case-insensitive duplicate tables/columns are rejected. See the [configuration guide](configuration.md) for the complete reserved-name list.

## Remaining constraints

- **No global snapshot guarantee.** Probing, counting, sizing, extraction, and verification use separate queries. Freeze the synthetic data; for authorized datasets, plan consistency externally. Do not infer transaction isolation from a checksum.
- **Ordering and pagination.** SQL rows are not intrinsically ordered. Offset-based and repeated aggregate reads require stable data and cannot be assumed safe for mutable tables.
- **Framing is not type preservation.** Length framing protects field boundaries, including embedded separators. It does not by itself guarantee native numeric/date types or lossless support for every binary/character type. The lab expects string or null values.
- **NULL sentinels can collide.** A genuine value identical to `null_marker` cannot be distinguished by sentinel substitution alone. Choose fixture values accordingly; this release does not claim general collision-free NULL serialization.
- **Capacity checks are estimates.** Response caps, SQL aggregate limits, packet limits, charset conversion, escaping, truncation, and middleware transformations can change independently. A measured slot size is not a permanent promise.
- **Database differences matter.** MariaDB 11.4 is the integration fixture. Compatibility with other MariaDB versions or MySQL requires real, version-specific tests; similarly named functions need not behave identically.
- **No blanket mode coverage.** The integration workflow checks `union` and `compress` on a small static table. It does not establish correctness for every extraction path or fallback.
- **Configuration is trusted input.** Endpoint templates and output settings are not a sandbox. Review them before use, restrict local file permissions, and use separate output directories.
- **The lab is intentionally vulnerable.** Loopback publication, SELECT-only grants, and container isolation reduce exposure but are not a guarantee against all SQL/resource abuse. Do not run it alongside sensitive workloads or publish it to a network.

A report, passing exit code, or successful HTTP response is not sufficient evidence of correctness. Keep raw verification outcomes and, for controlled experiments, compare the complete expected dataset.
