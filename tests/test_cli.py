"""CLI tests use real engines with offline query/transport boundaries."""
import builtins
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import re
import zlib
from unittest import mock

import boolrace


class OfflineTarget:
    """Deterministic query responses; parsing, stages, files and CRC run for real."""
    def __init__(self):
        self.queries = []
        self.schemas = ["lab"]
        self.current_db = "lab"

    def get(self, payload, *args, **kwargs):
        if "42524d41524b" in payload:
            value = "BRMARK"
        elif "4d524b3031" in payload:
            value = "MRK01"
        elif "REPEAT" in payload:
            size = int(re.search(r"REPEAT\(0x51,(\d+)\)", payload).group(1))
            value = "Q" * min(size, 1024)
        else:
            raise AssertionError("unexpected transport query: " + payload)
        return 200, ("<title>" + value + "</title>").encode(), 0

    def query(self, expr, *args, **kwargs):
        self.queries.append(expr)
        if expr == "DATABASE()":
            value = self.current_db
        elif "schema_name FROM information_schema.schemata" in expr:
            index = int(re.search(r"LIMIT (\d+),1", expr).group(1))
            value = self.schemas[index] if index < len(self.schemas) else "NULL"
        elif "table_name FROM information_schema.tables" in expr:
            value = "items" if "LIMIT 0,1" in expr else "NULL"
        elif "column_name FROM information_schema.columns" in expr:
            value = "id" if "LIMIT 0,1" in expr else "NULL"
        elif "GROUP_CONCAT(column_name)" in expr:
            value = ""
        elif "SUM(CRC32" in expr:
            value = str(zlib.crc32(b"7") & 0xffffffff)
        elif "JSON_ARRAYAGG" in expr:
            value = "5" if expr.startswith("LENGTH(") else '["7"]'
        else:
            value = "1"
        return value, 200, 0


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.cfg = self.base / "config.json"
        self.out = self.base / "out"
        self.write_config({})

    def write_config(self, overrides):
        config = {"output": {"dir": str(self.out)}, "extraction": {"throttle": 0}}
        self.cfg.write_text(json.dumps(boolrace.deep_merge(config, overrides)), encoding="utf-8")

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["boolrace.py", *args, "--config", str(self.cfg)]), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = boolrace.main()
            except SystemExit as exc:
                code = exc.code
        return code or 0, stdout.getvalue() + stderr.getvalue()

    def test_dry_run_has_no_engine_requests_or_writes(self):
        self.write_config({"tables": {"items": ["id"]}})
        real_open = builtins.open
        def readonly_open(path, mode="r", *args, **kwargs):
            self.assertFalse(any(flag in mode for flag in "wax+"), "dry-run attempted a write")
            return real_open(path, mode, *args, **kwargs)
        with mock.patch("boolrace.Engine", side_effect=AssertionError("dry-run created Engine")) as engine, mock.patch("builtins.open", side_effect=readonly_open), mock.patch.object(boolrace.Transport, "get", side_effect=AssertionError("request")) as request:
            code, output = self.invoke("all", "--dry-run", "--table", "items")
        self.assertEqual(code, 0)
        engine.assert_not_called()
        request.assert_not_called()
        self.assertFalse(self.out.exists())
        self.assertIn("items", output)
        self.assertIn("intent", output.lower())
        self.assertIn("all", output)


    def test_invalid_configuration_fails_before_engine(self):
        for overrides in ({"extraction": {"mode": "column"}}, {"extraction": {"mode": "typo"}}):
            with self.subTest(config=overrides):
                self.write_config(overrides)
                with mock.patch("boolrace.Engine", side_effect=AssertionError("invalid config reached engine")):
                    code, output = self.invoke("extract", "--dry-run")
                self.assertNotEqual(code, 0)
                self.assertIn("unsupported", output)
        self.cfg.unlink()
        code, output = self.invoke("probe", "--dry-run")
        self.assertNotEqual(code, 0)
        self.assertIn("config", output.lower())
        self.assertFalse(self.out.exists())

    def test_tls_verification_defaults_to_enabled(self):
        cfg = boolrace.load_cfg(str(self.cfg))
        self.assertIs(cfg["target"]["verify_tls"], True)
        cfg["target"].pop("verify_tls")
        transport = boolrace.Transport(cfg)
        self.assertTrue(transport.verify)
        self.assertIsNone(transport._tls)
        transport.close()


    def test_all_verifies_discovered_tables_without_duplicate_enumeration(self):
        target = OfflineTarget()
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
            code, output = self.invoke("all")
        self.assertEqual(code, 0, output)
        self.assertEqual(json.loads((self.out / "items.json").read_text())["rows"], [["7"]])
        verified = json.loads((self.out / "_verify.json").read_text())
        self.assertIn("items", verified, "all silently skipped verification of discovered tables")
        self.assertIs(verified["items"]["ok"], True)
        first_table_queries = [q for q in target.queries if "table_name FROM information_schema.tables" in q and "LIMIT 0,1" in q]
        self.assertEqual(len(first_table_queries), 1, "duplicate enumeration")


    def test_multi_schema_and_wrong_current_schema_fail_closed(self):
        for schemas, configured, current in ((["lab", "other"], None, "lab"), (["other"], None, "lab"), (["lab", "other"], "other", "lab")):
            with self.subTest(schemas=schemas, configured=configured):
                self.write_config({"target": {"schema": configured}} if configured else {})
                target = OfflineTarget()
                target.schemas, target.current_db = schemas, current
                with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
                    code, output = self.invoke("all")
                self.assertNotEqual(code, 0, output)
                self.assertIn("schema", output.lower())
                self.assertFalse((self.out / "items.json").exists())

    def test_configured_single_current_schema_is_selected(self):
        self.write_config({"target": {"schema": "lab"}})
        target = OfflineTarget()
        target.schemas = ["lab", "other"]
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
            code, output = self.invoke("all")
        self.assertEqual(code, 0, output)
        tables_queries = [q for q in target.queries if "table_name FROM information_schema.tables" in q]
        self.assertTrue(all("0x6c6162" in q for q in tables_queries), tables_queries)


    def test_extract_and_verify_failures_return_nonzero(self):
        self.write_config({"tables": {"items": ["id"]}})
        target = OfflineTarget()
        real_query = target.query
        def failure(expr, *args, **kwargs):
            if "JSON_ARRAYAGG" in expr or "SUM(CRC32" in expr:
                raise boolrace.QueryError("offline query failure")
            return real_query(expr, *args, **kwargs)
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=failure):
            code, output = self.invoke("extract")
        with self.subTest(stage="extract"):
            self.assertNotEqual(code, 0, output)
            self.assertFalse((self.out / "items.json").exists())
        for data in (None, {"table": "items", "cols": ["id"], "rows": [["7"]]}):
            with self.subTest(data=data):
                if data is not None:
                    (self.out / "items.json").write_text(json.dumps(data), encoding="utf-8")
                with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=failure):
                    code, output = self.invoke("verify")
                self.assertNotEqual(code, 0, output)
                result = json.loads((self.out / "_verify.json").read_text())
                self.assertIn("items", result)
                self.assertIsNot(result["items"]["ok"], True)

    def test_no_selected_tables_is_not_success(self):
        self.write_config({"tables": {"items": ["id"]}})
        target = OfflineTarget()
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
            code, output = self.invoke("verify", "--table", "absent")
        self.assertNotEqual(code, 0, output)
        self.assertIn("no tables", output.lower())

    def test_verification_mismatch_is_nonzero(self):
        self.write_config({"tables": {"items": ["id"]}})
        self.out.mkdir()
        (self.out / "items.json").write_text(json.dumps({"table": "items", "cols": ["id"], "rows": [["wrong"]]}), encoding="utf-8")
        target = OfflineTarget()
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
            code, output = self.invoke("verify")
        self.assertNotEqual(code, 0, output)
        self.assertIs(json.loads((self.out / "_verify.json").read_text())["items"]["ok"], False)


    def test_unsafe_table_filenames_rejected_before_io(self):
        names = ("../escape", "nested/items", "nested\\items", "C:escape", ".", "CON", "_verify", "items.", "bad`name")
        for name in names:
            with self.subTest(name=name):
                self.write_config({"tables": {name: ["id"]}})
                code, output = self.invoke("extract", "--dry-run")
                self.assertNotEqual(code, 0, output)
                self.assertIn("table", output.lower())
        self.assertFalse(self.out.exists())

    def test_output_table_symlink_cannot_escape_output_directory(self):
        self.write_config({"tables": {"items": ["id"]}})
        self.out.mkdir()
        outside = self.base / "outside.json"
        outside.write_text("keep", encoding="utf-8")
        try:
            (self.out / "items.json").symlink_to(outside)
        except OSError as exc:
            self.skipTest("symlink permission unavailable: %s" % exc)
        target = OfflineTarget()
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
            code, output = self.invoke("extract")
        self.assertNotEqual(code, 0, output)
        self.assertEqual(outside.read_text(), "keep")


    def test_engine_is_closed_after_success_and_failure(self):
        transports = []
        original_get = OfflineTarget().get
        def capture_get(transport, payload, *args, **kwargs):
            if transport not in transports:
                transports.append(transport)
                transport._conn()
                transport._pool(1)
            if "42524d41524b" in payload and fail:
                raise boolrace.SilentFailure("offline abort")
            return original_get(payload, *args, **kwargs)
        try:
            for fail in (False, True):
                with self.subTest(failure=fail):
                    with mock.patch.object(boolrace.Transport, "get", new=capture_get):
                        code, output = self.invoke("probe")
                    self.assertEqual(code, 1 if fail else 0, output)
                    transport = transports[-1]
                    self.assertIsNone(transport._pool_obj, "executor was not closed")
                    self.assertIsNone(transport._local.conn, "HTTP connection was not closed")
        finally:
            for transport in transports:
                transport._close_pool()
                transport.close()


    def test_report_is_explicitly_unsupported_without_output_creation(self):
        with mock.patch.object(boolrace.Transport, "get", side_effect=AssertionError("network")):
            code, output = self.invoke("report")
        self.assertNotEqual(code, 0, output)
        self.assertIn("unsupported", output.lower())
        self.assertFalse(self.out.exists())


    def test_verification_refuses_files_from_different_table_or_projection(self):
        self.write_config({"tables": {"items": ["id"]}})
        self.out.mkdir()
        for table, cols in (("other", ["id"]), ("items", ["other"])):
            with self.subTest(table=table, cols=cols):
                (self.out / "items.json").write_text(json.dumps({"table": table, "cols": cols, "rows": [["7"]]}), encoding="utf-8")
                target = OfflineTarget()
                with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=target.query):
                    code, output = self.invoke("verify")
                self.assertNotEqual(code, 0, output)
                self.assertFalse(any("SUM(CRC32" in q for q in target.queries))

    def test_duplicate_discovered_table_names_fail_closed(self):
        target = OfflineTarget()
        query = target.query
        def duplicate(expr, *args, **kwargs):
            if "table_name FROM information_schema.tables" in expr and "LIMIT 1,1" in expr:
                target.queries.append(expr)
                return "items", 200, 0
            return query(expr, *args, **kwargs)
        with mock.patch.object(boolrace.Transport, "get", side_effect=target.get), mock.patch.object(boolrace.Engine, "query", side_effect=duplicate):
            code, output = self.invoke("all")
        self.assertNotEqual(code, 0, output)
        self.assertIn("duplicate", output.lower())
        self.assertFalse((self.out / "items.json").exists())


    def test_invalid_projection_and_colliding_filenames_fail_before_network(self):
        for tables in ({"items": []}, {"items": "id"}, {"items": ["id", "id"]}, {"items": ["bad`name"]}, {"items": ["id"], "ITEMS": ["id"]}):
            with self.subTest(tables=tables):
                self.write_config({"tables": tables})
                code, output = self.invoke("extract", "--dry-run")
                self.assertNotEqual(code, 0, output)


if __name__ == "__main__":
    unittest.main()
