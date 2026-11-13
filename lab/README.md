# Disposable local MariaDB lab

This is a deliberately vulnerable fixture, not an application template. It executes the `id` query parameter inside a SELECT to expose exactly five reflected slots: one `<title>` and four `<p>` values. Values are HTML-escaped and each slot is capped at 8,192 characters. It does not emulate successful extraction results: SQL is executed by real MariaDB.

## Run

From the repository root, with Python 3.10+ and Docker Compose v2:

```sh
docker compose -f lab/compose.yml up --build --wait
python lab/smoke.py --mode compress --out boolrace_out/lab-smoke
python lab/smoke.py --mode union --out boolrace_out/lab-union
docker compose -f lab/compose.yml down --volumes
```

Use a new `--out` directory for every run. The runner never deletes an existing directory or treats stale output as current evidence. On failure, inspect the stage logs under the selected directory, and stop the lab when finished.

The DB stores data on a temporary filesystem. Stopping/recreating it resets the dataset; there are no durable data volumes to preserve. `seed.sql` inserts six explicitly synthetic rows, including NULL, empty text, Unicode, an embedded field separator, HTML-like text, negative/zero integers, and whitespace. `expected.json` independently specifies the exact string/null representation expected from row extraction.

## Network and privileges

- The only published port is **127.0.0.1:8099**. The DB has **no host port**.
- Compose connects both containers to an internal network. The web container listens on all interfaces *inside that container* solely for Docker port forwarding; host publication remains loopback-only.
- The web process runs as an unprivileged user with a read-only root filesystem, dropped capabilities, and no-new-privileges.
- The fixed `lab_reader` / `synthetic-only` login is public fixture data, not a secret. It has SELECT permission only on `boolrace_lab.*`. Never reuse it elsewhere.
- The web entrypoint refuses arbitrary DB hosts and host-side non-loopback binds. Container mode additionally requires the Docker marker file.
- Requests require the literal loopback Host header and reject browser cross-origin headers. These checks reduce accidental exposure; they are not an authentication boundary or a sandbox.
- Do not publish or tunnel this fixture. Local users/processes can still reach it. Do not attach it to real datasets, host database sockets, or sensitive networks.

The engine itself is configurable for authorized endpoints; the stricter loopback policy belongs to this lab runner. `smoke.py` accepts only `http://127.0.0.1:PORT/item.php?id=`, checks the fixture identity and seed count, disables proxy inheritance for subprocesses, and uses a direct non-redirecting health check. It intentionally rejects `localhost` to avoid DNS ambiguity.

## What the smoke test proves

For each run, `smoke.py` calls only the real `extract` and `verify` CLI stages with explicit `specimens` columns. It does **not** call `all`, `enumerate`, or scan other schemas. The runner requires:

1. A healthy real database-backed fixture with the expected row count.
2. Successful stage exit codes and fresh output files.
3. Exact equality of the complete extracted row multiset and `expected.json`, including duplicates, NULLs, and every value.
4. `_verify.json` containing `specimens.ok is True`, the expected row count, and matching server/local CRC sums.
5. A readable `lab-report.json` written by the runner only after all checks pass.

`lab-report.json` is the lab's independent summary of checked extraction and verification results. Native `report` is unsupported in v0.1.0 and exits with status 2, including with `--dry-run`; the smoke runner never calls it. Stage logs and stage JSON artifacts remain available alongside the lab summary. A missing file or unknown verification result fails the run. Do not use Python `-O`; the runner explicitly rejects optimized execution because its integrity checks use assertions.

The default smoke coverage is `compress`; CI runs both `union` and `compress`. It does not establish MySQL compatibility, mutable-table consistency, binary fidelity, every mode, large-data behavior, or performance.

## Development without Compose

The stdlib-only safety tests need no database or PyMySQL:

```sh
python -m unittest discover -s lab -p 'test_*.py' -v
```

For an already provisioned **disposable loopback MariaDB** only, initialize `seed.sql` in a fresh instance, then install the lab dependency into a separate virtual environment:

```sh
python -m venv .venv
# Activate the environment using your platform's activation command.
python -m pip install -r lab/requirements.txt
python lab/web.py --db-host 127.0.0.1 --db-port 3306
```

Do not run `seed.sql` against a database containing any real data. The engine does not need this dependency. CI instead joins a disposable MariaDB 11.4 service's Docker network and publishes the fixture on loopback; it never publishes the DB port.

Images track `mariadb:11.4` and `python:3.14-slim`; these are mutable tags, not bit-for-bit reproducible image digests. Record resolved digests and the actual database version for any benchmark. PyMySQL is pinned in `requirements.txt`. A network connection is required to obtain images and the lab dependency on first build.
