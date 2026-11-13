"""Offline safety/contract tests for the lab, not a database simulation."""
import importlib.util
from pathlib import Path
import unittest

LAB = Path(__file__).resolve().parent


class LoopbackPolicyTests(unittest.TestCase):
    def test_smoke_refuses_nonliteral_loopback_targets(self):
        path = LAB / "smoke.py"
        self.assertTrue(path.exists(), "the local-only smoke runner is not implemented")
        spec = importlib.util.spec_from_file_location("lab_smoke", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.validate_url("http://127.0.0.1:8099/item.php?id="),
                         "http://127.0.0.1:8099/item.php?id=")
        for url in (
            "http://192.0.2.1:8099/item.php?id=",
            "http://0.0.0.0:8099/item.php?id=",
            "http://localhost:8099/item.php?id=",
            "http://127.0.0.1.example.invalid:8099/item.php?id=",
            "http://user@127.0.0.1:8099/item.php?id=",
            "https://127.0.0.1:8099/item.php?id=",
            "http://127.0.0.1:8099/other?id=",
            "http://127.0.0.1:8099/item.php?id=#fragment",
            "http://127.0.0.1:8099/item.php?id=&other=1",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                module.validate_url(url)


    def test_remote_cli_arguments_fail_before_creating_output(self):
        import os
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory(dir=os.environ.get("BOOLRACE_TEST_TMPDIR")) as directory:
            output = Path(directory) / "must-not-exist"
            result = subprocess.run(
                [sys.executable, str(LAB / "smoke.py"), "--url",
                 "http://192.0.2.1:8099/item.php?id=", "--out", str(output)],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("lab URL must be", result.stderr)
            self.assertFalse(output.exists())


class ReportContractTests(unittest.TestCase):
    def test_smoke_main_uses_supported_stages_and_writes_verified_report(self):
        import io
        import json
        import os
        import subprocess
        import sys
        import tempfile
        from unittest.mock import patch

        spec = importlib.util.spec_from_file_location("lab_smoke", LAB / "smoke.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expected = json.loads((LAB / "expected.json").read_text(encoding="utf-8"))
        # Boundary fixtures exercise orchestration, not SQL or CRC computation.
        extracted = {**expected, "rows": list(reversed(expected["rows"]))}
        verification = {"specimens": {"ok": True, "rows": len(expected["rows"]),
                                      "server": "10", "local": 10}}
        stages = []
        with tempfile.TemporaryDirectory(dir=os.environ.get("BOOLRACE_TEST_TMPDIR")) as directory:
            output = Path(directory) / "smoke"

            def run_stage(command, **kwargs):
                stage = command[2]
                stages.append(stage)
                self.assertEqual(command[0], sys.executable)
                self.assertEqual(Path(command[1]), LAB.parent / "boolrace.py")
                self.assertEqual(Path(command[command.index("--out") + 1]), output)
                self.assertFalse((output / "lab-report.json").exists())
                artifacts = {"extract": ("specimens.json", extracted),
                             "verify": ("_verify.json", verification)}
                if stage not in artifacts:
                    return subprocess.CompletedProcess(command, 2, "", "report is unsupported\n")
                filename, content = artifacts[stage]
                (output / filename).write_text(json.dumps(content), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch("sys.argv", [str(LAB / "smoke.py"), "--out", str(output)]), \
                    patch("http.client.HTTPConnection") as http, \
                    patch("subprocess.run", side_effect=run_stage), \
                    patch("sys.stdout", new_callable=io.StringIO), \
                    patch("sys.stderr", new_callable=io.StringIO):
                response = http.return_value.getresponse.return_value
                response.status = 200
                response.read.return_value = json.dumps(
                    {"fixture": "boolrace-local-lab", "rows": len(expected["rows"])}
                ).encode("utf-8")
                module.main()
                http.assert_called_once_with("127.0.0.1", 8099, timeout=5)
                http.return_value.request.assert_called_once_with("GET", "/healthz")
                http.return_value.close.assert_called_once_with()

            self.assertEqual(stages, ["extract", "verify"])
            report = json.loads((output / "lab-report.json").read_text(encoding="utf-8"))
            self.assertEqual(report, {
                "fixture": "boolrace-local-lab", "mode": "compress",
                "rows": len(expected["rows"]), "exact_rows_match": True,
                "crc_verified": True,
                "commands": [{"stage": stage, "returncode": 0} for stage in stages],
                "verification": verification,
            })

    def test_smoke_requires_exact_rows_and_true_crc(self):
        spec = importlib.util.spec_from_file_location("lab_smoke", LAB / "smoke.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(hasattr(module, "check_results"), "result assertions are missing")
        columns = ["id", "label", "note"]
        rows = [["1", "synthetic", None], ["2", "測試", "a\x1fb"]]
        extracted = {"table": "specimens", "cols": columns, "rows": rows}
        verification = {"specimens": {"ok": True, "rows": 2, "server": "10", "local": 10}}
        module.check_results(extracted, verification, columns, rows)
        for bad in ({}, {"specimens": {"ok": None}}, {"specimens": {"ok": 1}},
                    {"specimens": {"ok": False}}):
            with self.subTest(verification=bad), self.assertRaises(AssertionError):
                module.check_results(extracted, bad, columns, rows)
        for badrows in (rows[:1], rows + [rows[0]], [["1", "synthetic", ""], rows[1]]):
            with self.subTest(rows=badrows), self.assertRaises(AssertionError):
                module.check_results({**extracted, "rows": badrows}, verification, columns, rows)


class FixtureContractTests(unittest.TestCase):
    def test_fixture_has_five_escaped_slots_and_rejects_remote_bind(self):
        path = LAB / "web.py"
        self.assertTrue(path.exists(), "the web fixture is not implemented")
        spec = importlib.util.spec_from_file_location("lab_web", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        page = module.render_row(["<script>", "測試", None, "a\x1fb", "5"])
        self.assertEqual(page.count("<title>"), 1)
        self.assertEqual(page.count("<p>"), 4)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)
        self.assertIn("<p>NULL</p>", page)
        self.assertEqual(module.validate_bind("127.0.0.1", container=False), "127.0.0.1")
        for host in ("192.0.2.1", "localhost", "0.0.0.0"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                module.validate_bind(host, container=False)


    def test_http_fixture_rejects_wrong_host_and_origin_without_database(self):
        import http.client
        from http.server import ThreadingHTTPServer
        import threading

        spec = importlib.util.spec_from_file_location("lab_web", LAB / "web.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for headers in ({"Host": "other.invalid"}, {"Origin": "http://other.invalid"},
                            {"Sec-Fetch-Site": "cross-site"}):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    connection.request("GET", "/item.php?id=1", headers=headers)
                    response = connection.getresponse()
                    self.assertEqual(response.status, 403)
                    response.read()
                finally:
                    connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
