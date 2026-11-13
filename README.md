# boolrace

[![CI](https://github.com/a5768549/boolrace/actions/workflows/ci.yml/badge.svg)](https://github.com/a5768549/boolrace/actions/workflows/ci.yml)

**v0.1.0 — experimental.** A small Python research engine for studying the integrity of MySQL/MariaDB data transported through a reflected `UNION` channel. Intended for disposable local labs and explicitly authorized testing only.

It is **not a sqlmap replacement**, a general vulnerability scanner, or a universally reliable database dumper. A successful HTTP response is not proof of a complete or correct extraction.

## Scope

- Configurable `UNION` shape and reflected response slots.
- Channel probing, capacity checks, row extraction, and server/local CRC comparison.
- Length-framed rows for values that contain field separators.
- A synthetic MariaDB 11.4 lab and an integration runner that compares every returned row with an independent fixture manifest.
- Python **3.10 or newer**, with **no third-party engine runtime dependencies**. Docker and PyMySQL are for the optional lab only.

`column` mode is disabled fail-closed in v0.1.0: independent column aggregates cannot establish row alignment or a consistent snapshot. Do not enable it by bypassing the guard. See [limitations](docs/limitations.md).

## Start with a disposable local lab

Prerequisites: Python 3.10+ and Docker with Compose v2. Run from the repository root:

```sh
docker compose -f lab/compose.yml up --build --wait
python lab/smoke.py --mode compress --out boolrace_out/first-run
# Optional second path, using a fresh output directory:
python lab/smoke.py --mode union --out boolrace_out/union-run
docker compose -f lab/compose.yml down --volumes
```

Only `127.0.0.1:8099` is published; the database has no host port. The fixture is deliberately vulnerable and uses a SELECT-only account against synthetic data. Never deploy it publicly, tunnel it, attach it to a production database, or run it on a shared/untrusted machine. [Lab details and cleanup](lab/README.md).

The runner calls only the `extract` and `verify` CLI stages. It fails unless both succeed, all expected row values and counts match, CRC verification is explicitly `true`, and its independent `lab-report.json` is written and readable. It refuses non-loopback targets, unknown paths, and existing output directories. It does not use `all` or enumerate unrelated schemas.

## Inspect and run the CLI

```sh
python boolrace.py --help
python boolrace.py extract --config examples/lab.json --dry-run
# With the local lab running:
python boolrace.py probe --config examples/lab.json
python boolrace.py extract --config examples/lab.json --table specimens
python boolrace.py verify --config examples/lab.json
```

`--dry-run` is an offline plan: no network requests and no output writes. It is not an exact SQL transcript or a prediction of runtime-discovered slots, sizes, or queries. Real `probe`, `extract`, and `verify` commands make requests. Read the [configuration guide](docs/configuration.md) before adapting a configuration.

Use explicit `tables` and the intended database/schema. Keep the fixture unchanged while extracting and verifying. Treat configuration files as trusted input, not as safe files to accept from strangers.

Outputs can contain sensitive data in authorized non-lab use. Keep them out of Git and restrict their filesystem access. `_verify.json` records verification results; the lab runner adds its own `lab-report.json`. Native `report` is unsupported in v0.1.0 and exits with status 2, including with `--dry-run`; existing stage JSON artifacts remain available. The independent lab summary is not an independent security certification.

## Tests and evidence

```sh
python -m unittest discover -s tests -v
python -m unittest discover -s lab -p 'test_*.py' -v
```

CI runs Ubuntu unit-test jobs on Python 3.10 and 3.14, plus a separate integration job using real MariaDB 11.4 and the local HTTP fixture. The release candidate passed both unit jobs and exact-row/CRC checks for `union` and `compress`; see the [verification record](docs/verification.md) for the tested revision, logs, and earlier failed experiments. This does not establish compatibility outside the documented fixture.

There is no published, validated speedup or cross-tool performance comparison. Historical timing claims are unverified. The [benchmark protocol](docs/benchmark.md) defines evidence to collect before making a performance claim.

## Security and limitations

CRC is a non-cryptographic consistency check, not authenticity, a collision-free proof, or snapshot isolation. Mutable tables, server limits, response transformations, and unsupported types may still invalidate results. See [limitations](docs/limitations.md) and [responsible use](docs/security.md).

Please report reproducible bugs using the synthetic lab, a minimal sanitized configuration, and exact commands. Do not post target addresses, credentials, extracted real data, or raw production request logs.

## 繁體中文摘要

boolrace v0.1.0 是實驗性的 MySQL/MariaDB `UNION` 回顯通道完整性研究工具，僅供本機靶場或明確授權的測試。它不是 sqlmap 替代品，也不保證能可靠擷取任意資料庫。

- 核心只需 Python 3.10+ 標準函式庫；Docker／PyMySQL 僅用於選用靶場。
- 範例只指向 `127.0.0.1`，資料庫不對主機開放連接埠；請勿公開部署或轉發靶場。
- 建議使用長度框架（`framing: length`）與明確的資料表清單；`column` 模式在此版本停用。
- `--dry-run` 只列出離線計畫，不連網、不寫輸出，也不是完整動態 SQL 清單。
- CRC 通過不代表密碼學驗證或一致性快照；歷史效能數字尚未驗證，沒有跨工具比較結論。

## License

[MIT](LICENSE), copyright 2026 a5768549.
