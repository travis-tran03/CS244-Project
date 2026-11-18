#!/usr/bin/env python3
"""IoT vertical-slice server: ingest signed sensor readings, store them, serve a dashboard.

Path:  BMP280 -> ESP32 -> Wi-Fi HTTP POST /api/readings -> this server (SQLite) -> dashboard (/)

Standard library only, so there is nothing to install.

Security notes (see README):
  * The shared key is read from the IOT_SHARED_KEY environment variable, never from the repo.
  * Every POST must carry X-Signature = hex(HMAC-SHA256(key, raw_body)). Unsigned or badly
    signed posts are rejected with 401, so there is no unauthenticated write path.
  * Readings are range-checked before they are stored.
  * Traffic is plain HTTP on the LAN: the signature proves who sent a reading, but does not
    hide it. Put TLS in front of this before leaving a trusted network.
"""
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
DB_PATH = os.environ.get("IOT_DB", str(HERE / "readings.db"))
HOST = os.environ.get("IOT_HOST", "0.0.0.0")
PORT = int(os.environ.get("IOT_PORT", "8000"))
MAX_BODY = 2048

# Physical sanity limits (BMP280 operating range: -40..85 C, 300..1100 hPa).
LIMITS = {"temp_c": (-40.0, 85.0), "pressure_hpa": (300.0, 1100.0)}

_db_lock = threading.Lock()
_db = None


def get_key() -> bytes:
    key = os.environ.get("IOT_SHARED_KEY", "")
    if len(key) < 8:
        sys.exit("Set IOT_SHARED_KEY (at least 8 characters) before starting the server.")
    return key.encode()


def init_db() -> None:
    global _db
    _db = sqlite3.connect(DB_PATH, check_same_thread=False)
    _db.execute(
        """CREATE TABLE IF NOT EXISTS readings (
               id            INTEGER PRIMARY KEY AUTOINCREMENT,
               received_at   REAL    NOT NULL,   -- server unix time, seconds
               device        TEXT    NOT NULL,
               seq           INTEGER NOT NULL,   -- device message counter (gap detection)
               uptime_s      INTEGER,
               temp_c        REAL    NOT NULL,
               pressure_hpa  REAL    NOT NULL,
               rssi          INTEGER
           )"""
    )
    _db.execute("CREATE INDEX IF NOT EXISTS idx_readings_time ON readings(received_at)")
    _db.commit()


def validate(doc: dict):
    """Return (clean_dict, None) or (None, error_message)."""
    if not isinstance(doc, dict):
        return None, "body must be a JSON object"
    device = doc.get("device")
    if not isinstance(device, str) or not (1 <= len(device) <= 32) or not device.isprintable():
        return None, "bad device"
    out = {"device": device}
    for field, (lo, hi) in LIMITS.items():
        v = doc.get(field)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not (lo <= v <= hi):
            return None, f"{field} missing or out of range [{lo}, {hi}]"
        out[field] = float(v)
    for field in ("seq", "uptime_s", "rssi"):
        v = doc.get(field)
        if v is not None and (isinstance(v, bool) or not isinstance(v, int)):
            return None, f"{field} must be an integer"
        out[field] = v
    if out["seq"] is None or out["seq"] < 0:
        return None, "seq required"
    return out, None


def row_to_dict(r) -> dict:
    return {
        "id": r[0], "t": r[1], "device": r[2], "seq": r[3], "uptime_s": r[4],
        "temp_c": r[5], "pressure_hpa": r[6], "rssi": r[7],
    }


COLS = "id, received_at, device, seq, uptime_s, temp_c, pressure_hpa, rssi"


class Handler(BaseHTTPRequestHandler):
    server_version = "iot-slice/1.0"

    def log_message(self, fmt, *args):  # one tidy line per request
        sys.stderr.write("%s  %s  %s\n" % (time.strftime("%H:%M:%S"), self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode())

    # ---------------------------------------------------------------- GET
    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path in ("/", "/index.html"):
            self._send(200, (HERE / "static" / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif url.path == "/api/latest":
            with _db_lock:
                r = _db.execute(f"SELECT {COLS} FROM readings ORDER BY id DESC LIMIT 1").fetchone()
            self._json(200, {"now": time.time(), "reading": row_to_dict(r) if r else None})
        elif url.path == "/api/readings":
            try:
                minutes = min(max(float(q.get("minutes", ["60"])[0]), 0.1), 60 * 24 * 30)
                limit = min(max(int(q.get("limit", ["2000"])[0]), 1), 20000)
            except ValueError:
                return self._json(400, {"error": "bad query"})
            since = time.time() - minutes * 60
            with _db_lock:
                rows = _db.execute(
                    f"SELECT {COLS} FROM (SELECT {COLS} FROM readings WHERE received_at >= ? "
                    f"ORDER BY id DESC LIMIT ?) ORDER BY id ASC",
                    (since, limit),
                ).fetchall()
                total = _db.execute("SELECT COUNT(*) FROM readings").fetchone()[0]
            self._json(200, {"now": time.time(), "total": total, "readings": [row_to_dict(r) for r in rows]})
        elif url.path == "/healthz":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    # --------------------------------------------------------------- POST
    def do_POST(self):
        if urlparse(self.path).path != "/api/readings":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._json(400, {"error": "bad length"})
        if not (0 < length <= MAX_BODY):
            return self._json(413, {"error": "body size"})
        body = self.rfile.read(length)

        sig = self.headers.get("X-Signature", "")
        expected = hmac.new(self.server.key, body, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig.lower(), expected):
            sys.stderr.write("  REJECTED: bad or missing signature\n")
            return self._json(401, {"error": "bad signature"})

        try:
            clean, err = validate(json.loads(body))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._json(400, {"error": "bad json"})
        if err:
            return self._json(422, {"error": err})

        with _db_lock:
            _db.execute(
                "INSERT INTO readings (received_at, device, seq, uptime_s, temp_c, pressure_hpa, rssi) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), clean["device"], clean["seq"], clean["uptime_s"],
                 clean["temp_c"], clean["pressure_hpa"], clean["rssi"]),
            )
            _db.commit()
        sys.stderr.write(
            f"  STORED {clean['device']} seq={clean['seq']} "
            f"T={clean['temp_c']:.2f}C P={clean['pressure_hpa']:.2f}hPa\n"
        )
        self._json(200, {"ok": True})


def main() -> None:
    key = get_key()
    init_db()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    srv.key = key
    print(f"Dashboard: http://localhost:{PORT}/   (listening on {HOST}:{PORT}, db={DB_PATH})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
