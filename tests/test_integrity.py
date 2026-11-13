"""Offline regression tests: no real target is contacted."""
import copy
import unittest
from unittest import mock

import boolrace


class FramedRowsTests(unittest.TestCase):
    def test_malformed_frames_are_rejected(self):
        for frame in ("5:ab", "-1:x", "+1:x", " 1:x", "１:x", "1:xy", "1:x\x1f", ":x"):
            with self.subTest(frame=frame):
                self.assertIsNone(boolrace.Engine._unframe_row(frame, 1))
        cfg = copy.deepcopy(boolrace.DEFAULT_CONFIG)
        cfg["extraction"]["framing"] = "length"
        engine = boolrace.Engine(cfg)
        try:
            with self.assertRaises(boolrace.SilentFailure):
                engine._decode_rows('["5:ab"]', ["value"])
        finally:
            engine.close()

    def test_frames_preserve_unicode_empty_values_and_separators(self):
        self.assertEqual(
            boolrace.Engine._unframe_row("4:café\x1f0:\x1f3:a\x1fb", 3),
            ["café", "", "a\x1fb"],
        )
        self.assertIsNone(boolrace.Engine._unframe_row("1:a|1:b", 2))


class ExtractionModeTests(unittest.TestCase):
    def test_unsupported_modes_fail_before_query(self):
        for mode in ("column", "typo"):
            with self.subTest(mode=mode):
                cfg = copy.deepcopy(boolrace.DEFAULT_CONFIG)
                cfg["extraction"]["mode"] = mode
                engine = boolrace.Engine(cfg)
                try:
                    with mock.patch.object(engine, "query", side_effect=AssertionError("network reached")) as query:
                        with self.assertRaisesRegex(ValueError, "unsupported|Unsupported"):
                            engine.extract_table("items", ["id"])
                        query.assert_not_called()
                finally:
                    engine.close()


class VerificationTests(unittest.TestCase):
    def test_scalar_integers_are_normalized_and_other_types_unverified(self):
        import zlib
        cfg = copy.deepcopy(boolrace.DEFAULT_CONFIG)
        engine = boolrace.Engine(cfg)
        joined = "42\x1f-7\x1f" + cfg["extraction"]["null_marker"]
        crc = zlib.crc32(joined.encode()) & 0xffffffff
        def query(expr, *args, **kwargs):
            if "information_schema" in expr:
                return "", 200, 0
            return str(crc), 200, 0
        try:
            with mock.patch.object(engine, "query", side_effect=query):
                try:
                    result = engine.verify_table("items", ["a", "b", "c"], [[42, -7, None]])
                except TypeError as exc:
                    self.fail("scalar integer verification crashed: %s" % exc)
                self.assertIs(result["ok"], True)
                for value in (1.5, True, {}, [], b"x"):
                    with self.subTest(value=value):
                        self.assertIsNone(engine.verify_table("items", ["a"], [[value]])["ok"])
        finally:
            engine.close()


class VerificationFailureTests(unittest.TestCase):
    def test_empty_response_does_not_verify_zero_checksum_rows(self):
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        try:
            with mock.patch.object(engine, "query", return_value=("", 200, 0)):
                self.assertIsNot(engine.verify_table("items", ["id"], [[""]])["ok"], True)
                self.assertIsNot(engine.verify_table("items", ["id"], [])["ok"], True)
        finally:
            engine.close()

    def test_malformed_rows_are_unverified(self):
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        try:
            with mock.patch.object(engine, "query", return_value=("0", 200, 0)):
                for rows in ([[]], [["", ""]], [""], {}):
                    with self.subTest(rows=rows):
                        self.assertIsNone(engine.verify_table("items", ["id"], rows)["ok"])
        finally:
            engine.close()

    def test_empty_table_null_checksum_needs_explicit_empty_rows(self):
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        try:
            with mock.patch.object(engine, "query", return_value=("NULL", 200, 0)):
                self.assertIs(engine.verify_table("items", ["id"], [])["ok"], True)
                self.assertIsNot(engine.verify_table("items", ["id"], [[""]])["ok"], True)
        finally:
            engine.close()


class DecodeShapeTests(unittest.TestCase):
    def test_non_array_and_non_string_aggregates_are_rejected(self):
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        try:
            for text in ('{}', '""', 'null', '[null]', '[7]', '[{}]'):
                with self.subTest(text=text):
                    with self.assertRaises(boolrace.SilentFailure):
                        engine._decode_rows(text, ["id"])
        finally:
            engine.close()

    def test_slices_query_failure_cannot_look_like_partial_success(self):
        cfg = copy.deepcopy(boolrace.DEFAULT_CONFIG)
        cfg["extraction"].update(mode="slices", throttle=0)
        engine = boolrace.Engine(cfg)
        try:
            for results in (("2", "7", boolrace.QueryError("failed")), ("2", "7", "NULL")):
                with self.subTest(results=results):
                    def query(expr, *args, **kwargs):
                        value = next(values)
                        if isinstance(value, Exception):
                            raise value
                        return value, 200, 0
                    values = iter(results)
                    with mock.patch.object(engine, "query", side_effect=query):
                        with self.assertRaises((boolrace.QueryError, boolrace.SilentFailure)):
                            engine.extract_table("items", ["id"])
        finally:
            engine.close()


class MetadataFailureTests(unittest.TestCase):
    def test_binary_metadata_failure_is_unverified(self):
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        def query(expr, *args, **kwargs):
            if "information_schema" in expr:
                raise boolrace.QueryError("metadata unavailable")
            return "1790921346", 200, 0
        try:
            with mock.patch.object(engine, "query", side_effect=query):
                result = engine.verify_table("items", ["id"], [["7"]])
            self.assertIsNone(result["ok"], "unknown binary serialization cannot be verified")
        finally:
            engine.close()

    def test_slice_count_failure_is_not_an_empty_success(self):
        cfg = copy.deepcopy(boolrace.DEFAULT_CONFIG)
        cfg["extraction"]["mode"] = "slices"
        engine = boolrace.Engine(cfg)
        def query(expr, *args, **kwargs):
            if "COUNT(*)" in expr:
                raise boolrace.QueryError("count unavailable")
            return "NULL", 200, 0
        try:
            with mock.patch.object(engine, "query", side_effect=query):
                with self.assertRaises((boolrace.QueryError, boolrace.SilentFailure)):
                    engine.extract_table("items", ["id"])
        finally:
            engine.close()


class CleanupTests(unittest.TestCase):
    def test_close_releases_worker_connections(self):
        from concurrent.futures import ThreadPoolExecutor
        engine = boolrace.Engine(copy.deepcopy(boolrace.DEFAULT_CONFIG))
        with ThreadPoolExecutor(max_workers=1) as pool:
            connection = pool.submit(engine.tp._conn).result()
        # Socket-like object keeps close observable without any network.
        class Socket:
            closed = False
            def close(self):
                self.closed = True
        sock = Socket()
        connection.sock = sock
        try:
            engine.close()
            self.assertTrue(sock.closed, "worker HTTP connection leaked")
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
