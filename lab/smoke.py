#!/usr/bin/env python3
"""Exercise the real CLI against the synthetic loopback MariaDB fixture."""
from urllib.parse import urlsplit


def validate_url(url):
    """No DNS, proxies, credentials, redirects, or arbitrary target paths."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None
            or parsed.path != "/item.php" or parsed.query != "id="
            or parsed.fragment or not parsed.port):
        raise ValueError("lab URL must be http://127.0.0.1:PORT/item.php?id=")
    return url


def check_results(extracted, verification, columns, expected):
    """Compare complete row multisets; a zero exit code alone is not success."""
    from collections import Counter

    assert extracted.get("table") == "specimens", "wrong table"
    assert extracted.get("cols") == columns, "column projection changed"
    rows = extracted.get("rows")
    assert isinstance(rows, list) and len(rows) == len(expected), "row count mismatch"
    assert Counter(map(tuple, rows)) == Counter(map(tuple, expected)), "row values differ"
    result = verification.get("specimens", {})
    assert result.get("ok") is True, "CRC verification did not explicitly pass"
    assert result.get("rows") == len(expected), "verification row count mismatch"
    assert int(result["server"]) == result["local"], "server/local CRC mismatch"


def main():
    import argparse
    import http.client
    import json
    import os
    from pathlib import Path
    import subprocess
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8099/item.php?id=")
    parser.add_argument("--mode", choices=["union", "compress"], default="compress")
    parser.add_argument("--out", default="boolrace_out/lab-smoke")
    args = parser.parse_args()
    if not __debug__:
        parser.error("do not run smoke.py with -O: integrity assertions must be enabled")
    try:
        url = validate_url(args.url)
    except ValueError as exc:
        parser.error(str(exc))
    root = Path(__file__).resolve().parent.parent
    expected = json.loads((root / "lab" / "expected.json").read_text(encoding="utf-8"))
    # http.client bypasses proxy environment variables and does not follow redirects.
    connection = http.client.HTTPConnection("127.0.0.1", urlsplit(url).port, timeout=5)
    try:
        connection.request("GET", "/healthz")
        response = connection.getresponse()
        assert response.status == 200, "fixture health check failed"
        health = json.loads(response.read())
        assert health == {"fixture": "boolrace-local-lab", "rows": len(expected["rows"])}, "wrong fixture/seed"
    finally:
        connection.close()
    out = Path(args.out).resolve()
    # Never reuse old files as evidence for a new run or remove an existing directory.
    out.mkdir(parents=True, exist_ok=False)
    config = json.loads((root / "examples" / "lab.json").read_text(encoding="utf-8"))
    config["target"]["base_url"] = url
    config["extraction"]["mode"] = args.mode
    config["output"]["dir"] = str(out)
    config_path = out / "lab-config.json"
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    environment = {key: value for key, value in os.environ.items()
                   if key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    environment["NO_PROXY"] = "127.0.0.1"
    environment["PYTHONUTF8"] = "1"
    commands = []
    for stage in ("extract", "verify"):
        command = [sys.executable, str(root / "boolrace.py"), stage,
                   "--config", str(config_path), "--out", str(out)]
        result = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=180)
        (out / (stage + ".log")).write_text(result.stdout + result.stderr, encoding="utf-8")
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        assert result.returncode == 0, "%s failed: exit %d" % (stage, result.returncode)
        commands.append({"stage": stage, "returncode": result.returncode})
    extracted = json.loads((out / "specimens.json").read_text(encoding="utf-8"))
    verification = json.loads((out / "_verify.json").read_text(encoding="utf-8"))
    check_results(extracted, verification, expected["cols"], expected["rows"])
    report = {"fixture": "boolrace-local-lab", "mode": args.mode,
              "rows": len(extracted["rows"]), "exact_rows_match": True,
              "crc_verified": True, "commands": commands,
              "verification": verification}
    report_path = out / "lab-report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    assert json.loads(report_path.read_text(encoding="utf-8")) == report
    print("PASS: %d exact synthetic rows, matching CRC, report: %s" % (report["rows"], report_path))


if __name__ == "__main__":
    main()
