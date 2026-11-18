# CS 244P IoT Project: Vertical Slice

One real sensor value travels the whole path and shows up on a dashboard:

```
BMP280 --I2C--> ESP32 --Wi-Fi, HTTP POST (HMAC-signed)--> Python server (SQLite) --> web dashboard
```

| Piece | Where | What it does |
|---|---|---|
| Firmware | `firmware/` | Reads BMP280 temperature (C) and pressure (hPa) every 5 s, signs and POSTs it. LEDs and OLED show status. Reconnects Wi-Fi on its own. |
| Server | `server/server.py` | Verifies the signature, range-checks, stores in SQLite, serves the API and dashboard. Standard library only. |
| Dashboard | `server/static/index.html` | Live value with LIVE/STALE badge, history charts (5 min to 3 days), recent table, missing-message counter. |
| Simulator | `tools/fake_device.py` | Software stand-in for the ESP32, for testing only. **Do not use it for the check.** |

## Setup (once)

1. Install [PlatformIO](https://platformio.org/) (VS Code extension, or `pip install platformio`) and Python 3.
2. Pick a long random shared key, e.g. `python -c "import secrets; print(secrets.token_urlsafe(24))"`.
3. Copy `firmware/include/secrets.h.example` to `firmware/include/secrets.h` and fill in the Wi-Fi name and password, the laptop's IP address (`ipconfig`) in `SERVER_URL`, the shared key, and a device name. This file is git-ignored; never commit it.
4. The ESP32 and laptop must be on the **same network**, and that network must allow device-to-device traffic. Many campus networks (eduroam, UCI-Wireless) do not. If the board can't reach the laptop, use a phone hotspot or a travel router.
5. Allow inbound TCP on the server port in the laptop firewall (Windows prompts the first time Python listens: allow **Private** networks).

## Run it

```powershell
# Terminal 1: server (PowerShell; use `export` on macOS/Linux)
$env:IOT_SHARED_KEY = "<the same key as in secrets.h>"
python server/server.py            # dashboard at http://localhost:8000/

# Terminal 2: firmware
cd firmware
pio run -t upload
pio device monitor                 # 115200 baud
```

Optional environment variables: `IOT_PORT` (default 8000), `IOT_DB` (SQLite path), `IOT_HOST` (default 0.0.0.0).

## Vertical-slice check: what to show the TA

1. Server running, dashboard open at `http://localhost:8000/`.
2. Board powered. Serial shows `BMP280: found at 0x76` and `POST seq=N T=..C P=..hPa -> 200`.
3. Dashboard badge is **LIVE** and temperature and pressure match what the serial log printed.
4. Make the value change physically: cup your hand around the BMP280 or breathe on it. Temperature visibly rises on the dashboard within a few seconds and shows up in the history chart. This shows the number is real and not canned.
5. Be ready to point at each hop: sensor wiring (D21/D22), `postReading()` in `firmware/src/main.cpp`, the server log line `STORED ...`, and the SQLite row.

Board indicators: green LED = last POST accepted, red = problem (Wi-Fi, sensor or POST), yellow = sending.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `BMP280: NOT FOUND` | SDA/SCL swapped or loose ground. Run the Lab 1 kit check: the I2C line should list `0x76`. |
| `POST ... -> -1` (negative) | Board can't reach the laptop: wrong IP in `SERVER_URL`, firewall, or network isolates clients. Test `http://<laptop-ip>:8000/healthz` from your phone on the same Wi-Fi. |
| `POST ... -> 401` | `SHARED_KEY` in `secrets.h` differs from `IOT_SHARED_KEY` on the server. |
| `POST ... -> 422` | Reading outside physical range, so likely a bad sensor. |
| Dashboard shows STALE | No reading for over 30 s. Check the board and server log. |
| Pressure far from ~1000 hPa | Fine at altitude; a clone may differ slightly. Values outside 300 to 1100 hPa are rejected. |

## Test without hardware

```powershell
$env:IOT_SHARED_KEY = "test-key-12345"; python server/server.py      # terminal 1
python tools/fake_device.py --count 20 --interval 1                  # terminal 2: expect HTTP 200
python tools/fake_device.py --count 1 --bad-signature                # expect HTTP 401
```

## Security decisions (for the Security Code Review)

- **No credentials in the repo.** Wi-Fi password and shared key live in `firmware/include/secrets.h` (git-ignored); the server reads its key from an environment variable. `firmware/include/secrets.h.example` has placeholders only.
- **No unauthenticated write path.** The server only accepts `POST /api/readings` with `X-Signature = HMAC-SHA256(key, body)`, compared in constant time. There are no command endpoints.
- **Input validation.** Body size limit, JSON schema check and physical range limits before anything is stored; SQL uses bound parameters.

Known gaps (to address later, documented honestly):

- Traffic is **plain HTTP**: readings can be read on the LAN and a captured message could be replayed. A signature proves origin, not freshness. Next steps: TLS, and a timestamp or nonce in the signed body.
- The dashboard and read APIs are **unauthenticated**, so keep the server on a trusted network.
- The HMAC key is a symmetric key stored in flash. The plan for the final system is to sign with the ATECC608A (Lab 6) so the key never leaves the chip.
- Not yet done: persistent buffering while the server is down, the 72-hour reliability run, and logging gaps to explain them. The `seq` counter and dashboard "missing messages" figure are the first step.
