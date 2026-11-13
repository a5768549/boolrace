# Release verification

This is a narrow reproducible lab result, not a claim of general extraction reliability.

The release candidate's code at `5067c1d1a9b838bf4047c41e4dbf7623c6e7497e` passed [GitHub Actions run 43490902337](https://github.com/a5768549/boolrace/actions/runs/43490902337):

| Check | Actual result |
| --- | --- |
| Ubuntu / Python 3.10 | 31 engine tests and 6 lab tests passed |
| Ubuntu / Python 3.14 | 31 engine tests and 6 lab tests passed |
| MariaDB 11.4.13 / `union` mode | All 6 expected synthetic rows matched; server/local CRC sum matched |
| MariaDB 11.4.13 / `compress` mode | All 6 expected synthetic rows matched; server/local CRC sum matched |
| Container build and service startup | Lab Dockerfile built; local HTTP fixture reached the real seeded DB |
| Compose | Configuration validated; standalone Compose startup was not exercised in that run |

The same offline suites also passed locally on Windows with Python 3.10 and 3.14. Real integration ran on the GitHub-hosted runner, not the maintainer's Windows machine.

Both modes returned the fixture CRC sum `12883841239`. The expected manifest includes NULL, empty text, Unicode, an embedded separator, markup, and whitespace. `lab/smoke.py` compares whole row multisets, not just a checksum or exit status.

## Earlier failed experiments

The original DISTINCT `UNION` fixture produced MariaDB error 126 and a signal 11 crash ([run](https://github.com/a5768549/boolrace/actions/runs/43489673256)). Changing to `UNION ALL` removed that observed crash but exposed text/JSON collation error 1271 ([run](https://github.com/a5768549/boolrace/actions/runs/43490147128)). The shipped fixture uses `UNION ALL` with byte-oriented output projections; the successful result above applies to that configuration only.

Do not infer that the engine fixes either database behavior for arbitrary endpoints. See [limitations](limitations.md). No performance benchmark, cross-tool comparison, mutable-table consistency, cryptographic integrity, MySQL integration, or universal binary preservation has been established.
