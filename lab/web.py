#!/usr/bin/env python3
"""Intentionally vulnerable SQL reflection fixture. Synthetic local lab ONLY."""
import argparse
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

SLOT_LIMIT = 8192


def validate_bind(host, container=False):
    if host == "127.0.0.1":
        return host
    # Docker publishes this container socket ONLY on host 127.0.0.1.
    if host == "0.0.0.0" and container and Path("/.dockerenv").exists():
        return host
    raise ValueError("bind must be 127.0.0.1 (container mode requires Docker)")


def render_row(row):
    values = []
    for value in row:
        if isinstance(value, bytes):
            value = value.decode("utf-8", "strict")
        value = "NULL" if value is None else str(value)
        values.append(escape(value[:SLOT_LIMIT], quote=True))
    if len(values) != 5:
        raise ValueError("fixture requires exactly five reflected columns")
    return ("<!doctype html><html><head><meta charset='utf-8'><title>"
            + values[0] + "</title></head><body>"
            + "".join("<p>" + value + "</p>" for value in values[1:])
            + "</body></html>")


def connect(host, port):
    import pymysql  # Optional lab dependency; never imported by boolrace.py.
    return pymysql.connect(
        host=host, port=port, user="lab_reader", password="synthetic-only",
        database="boolrace_lab", charset="utf8mb4", autocommit=True,
        connect_timeout=3, read_timeout=10, write_timeout=10,
        init_command="SET SESSION max_statement_time=3",
    )


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BoolraceLocalFixture/0.1"

    def respond(self, status, body, content_type="text/plain; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Discourage DNS rebinding and browser cross-origin requests. Not a sandbox.
        if self.headers.get("Host") != "127.0.0.1:%d" % self.server.server_port:
            self.respond(403, "local Host header required")
            return
        if self.headers.get("Origin") or self.headers.get("Sec-Fetch-Site") in ("cross-site", "same-site"):
            self.respond(403, "cross-origin requests are not part of this lab")
            return
        parsed = urlsplit(self.path)
        if parsed.path not in ("/healthz", "/item.php"):
            self.respond(404, "not found")
            return
        params = parse_qs(parsed.query, keep_blank_values=True)
        if parsed.path == "/item.php" and (set(params) != {"id"} or len(params["id"]) != 1):
            self.respond(400, "one id parameter required")
            return
        try:
            with connect(self.server.db_host, self.server.db_port) as db:
                with db.cursor() as cursor:
                    if parsed.path == "/healthz":
                        cursor.execute("SELECT COUNT(*) FROM specimens")
                        count = cursor.fetchone()[0]
                        self.respond(200, json.dumps({"fixture": "boolrace-local-lab", "rows": count}),
                                     "application/json; charset=utf-8")
                        return
                    # Deliberate injection point. NEVER copy this into an application.
                    # Binary projection makes this fixture's reflection byte-oriented;
                    # it avoids mixing application and JSON expression collations.
                    query = ("SELECT CAST(id AS BINARY), CAST(label AS BINARY), "
                             "CAST(COALESCE(note,'') AS BINARY), "
                             "CAST(quantity AS BINARY), CAST('synthetic' AS BINARY) "
                             "FROM specimens WHERE id=" + params["id"][0])
                    cursor.execute(query)
                    row = cursor.fetchone()
            self.respond(200, render_row(row or ["", "", "", "", ""]), "text/html; charset=utf-8")
        except Exception as exc:
            # Numeric DB error codes aid fixture diagnostics without logging SQL.
            code = exc.args[0] if exc.args and type(exc.args[0]) is int else "unknown"
            print("fixture query error: %s code=%s" % (type(exc).__name__, code), flush=True)
            self.respond(500, "SQL query error: " + type(exc).__name__)

    def log_message(self, format, *args):
        # Do not log SQL in request URLs. CI already records command-level failures.
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=3306)
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()
    try:
        bind = validate_bind(args.bind, args.container)
        allowed_db = {"127.0.0.1", "db"} if args.container and Path("/.dockerenv").exists() else {"127.0.0.1"}
        if args.db_host not in allowed_db:
            raise ValueError("only the loopback DB or the Compose db service is allowed")
    except ValueError as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer((bind, args.port), Handler)
    server.db_host = args.db_host
    server.db_port = args.db_port
    print("Synthetic lab fixture listening on %s:%d" % server.server_address, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
