#!/usr/bin/env python3
"""Pretend to be the ESP32, for testing the server + dashboard without hardware.

NOT for the vertical-slice demo: that must use a real sensor value from the real board.

  set IOT_SHARED_KEY=...   (same key the server uses)
  python tools/fake_device.py [--url http://localhost:8000] [--count 10] [--interval 2]
  python tools/fake_device.py --bad-signature      # must be rejected with 401
"""
import argparse
import hashlib
import hmac
import json
import math
import os
import time
import urllib.error
import urllib.request


def post(url: str, key: bytes, doc: dict, sign_with: bytes = None) -> int:
    body = json.dumps(doc, separators=(",", ":")).encode()
    sig = hmac.new(sign_with or key, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        url + "/api/readings", data=body,
        headers={"Content-Type": "application/json", "X-Signature": sig}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--bad-signature", action="store_true")
    a = ap.parse_args()
    key = os.environ.get("IOT_SHARED_KEY", "").encode()
    if not key:
        raise SystemExit("set IOT_SHARED_KEY")
    t0 = time.time()
    for seq in range(a.count):
        doc = {"device": "fake-01", "seq": seq, "uptime_s": int(time.time() - t0),
               "temp_c": round(22 + 1.5 * math.sin(seq / 5), 2),
               "pressure_hpa": round(1013 + 0.5 * math.cos(seq / 7), 2), "rssi": -55}
        code = post(a.url, key, doc, sign_with=b"wrong-key-wrong" if a.bad_signature else None)
        print(f"seq={seq} -> HTTP {code}")
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
