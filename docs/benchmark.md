# Benchmark protocol (no published performance claim)

Historical speedup figures are **unverified**. This release publishes no validated speedup, throughput baseline, or cross-tool comparison. In particular, there is no evidence here that boolrace is faster than sqlmap or that two tools perform equivalent work. The smoke test is a correctness check, not a benchmark.

## Reproducible experiment requirements

1. Use only disposable, authorized synthetic data. Record the exact generator/seed, row count, ordered projection, value distribution, NULL frequency, text/binary types, charset, and total logical data size. Commit the generator, not extracted real data.
2. Record the repository revision, Python version, OS/CPU/memory, Docker version, resolved container image digests, DB version/settings, web fixture revision, slot count/caps, and network topology. Image tags alone are not reproducible identifiers.
3. Freeze the dataset. Record relevant aggregate/packet limits and the consistency assumptions. Do not benchmark `column` mode while it is disabled.
4. Define scope before timing: either full workflow (probe through verification) or extraction only. Report setup, probe, extraction, and verification separately, and include failures and retries. Do not silently exclude discovery work from one candidate but not another.
5. Fix workers, request throttling, retry policy, connection reuse, compression, framing, projection, and output format. Record all configuration. Use the same channel capacity and constraints for every within-tool comparison.
6. Measure wall-clock duration with a monotonic clock, HTTP request counts, response bytes, verified rows, and verification outcome. Keep client and server resource observations if making efficiency claims.
7. Separate warm-up from measured runs. Run at least five independent measured trials per configuration, randomize configuration order, and report every run plus median/range. State cache conditions; do not claim cold-cache results without actually controlling them.
8. Require exact row-multiset equality and expected row count for every trial, in addition to server/local CRC agreement. Record incomplete or wrong results as failures, never as fast successful runs.
9. Preserve machine-readable results, exact invocation, logs, and the independent expected-data manifest in a sanitized reproducibility bundle. Do not fabricate missing trials or substitute unit-test timings for database measurements.

## Suggested result fields

`revision`, `python`, `db_version`, `image_digests`, `fixture_revision`, `seed`, `mode`, `workers`, `chunk`, `slot_capacity`, `scope`, `trial`, `duration_seconds`, `requests`, `response_bytes`, `expected_rows`, `actual_rows`, `exact_rows_match`, `crc_ok`, `exit_code`, `failure_reason`.

This is a proposed measurement schema, not a results table. There are no example numbers to mistake for measured output.

## Cross-tool comparisons

Do not publish a comparative speedup without demonstrating that both tools receive the same authorization scope, use a comparable channel, return the same complete values, perform the same discovery/verification work, and run with disclosed tuning. If those conditions cannot be met, describe separate experiments rather than ranking tools.
