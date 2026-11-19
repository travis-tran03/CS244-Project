#!/usr/bin/env python3
"""Pretend to be the ESP32, for testing the server + dashboard without hardware.

NOT for the vertical-slice demo: that must use a real sensor value from the real board.

  set IOT_SHARED_KEY=...   (same key the server uses)
  python tools/fake_device.py [--url http://localhost:8000] [--count 10] [--interval 2]
  python tools/fake_device.py --bad-signature      # must be rejected with 401
  python tools/fake_device.py --replay             # second send of the same message: 409
  python tools/fake_device.py --url https://localhost:8443 --cafile server/cert.pem
"""
import argparse
import hashlib
import hmac
import json
import math
import os
import secrets
import ssl
import time
import urllib.error
import urllib.request


def post(url: str, key: bytes, doc: dict, sign_with: bytes = None, ctx=None) -> int:
    body = json.dumps(doc, separators=(",", ":")).encode()
    sig = hmac.new(sign_with or key, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        url + "/api/readings", data=body,
        headers={"Content-Type": "application/json", "X-Signature": sig}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--bad-signature", action="store_true")
    ap.add_argument("--replay", action="store_true", help="send each message twice; the 2nd must be 409")
    ap.add_argument("--cafile", help="PEM to trust for https:// URLs (self-signed server cert)")
    a = ap.parse_args()
    key = os.environ.get("IOT_SHARED_KEY", "").encode()
    if not key:
        raise SystemExit("set IOT_SHARED_KEY")
    ctx = ssl.create_default_context(cafile=a.cafile) if a.url.startswith("https") else None
    boot_id = secrets.token_hex(4)
    t0 = time.time()
    for seq in range(a.count):
        doc = {"device": "fake-01", "boot_id": boot_id, "seq": seq, "uptime_s": int(time.time() - t0),
               "temp_c": round(22 + 1.5 * math.sin(seq / 5), 2),
               "pressure_hpa": round(1013 + 0.5 * math.cos(seq / 7), 2), "rssi": -55}
        sign_with = b"wrong-key-wrong" if a.bad_signature else None
        code = post(a.url, key, doc, sign_with=sign_with, ctx=ctx)
        print(f"seq={seq} -> HTTP {code}")
        if a.replay:
            print(f"seq={seq} (replayed) -> HTTP {post(a.url, key, doc, ctx=ctx)}")
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
