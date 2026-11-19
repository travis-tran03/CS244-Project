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
$env:IOT_SHARED_KEY = "<the same key as in secrets.h>"   # >= 16 chars, random
$env:IOT_DASH_PASSWORD = "<a different long password>"      # dashboard login (user: admin)
python server/server.py            # dashboard at http://localhost:8000/ (browser asks for login)

# Terminal 2: firmware
cd firmware
pio run -t upload
pio device monitor                 # 115200 baud
```

Optional environment variables: `IOT_PORT` (default 8000), `IOT_DB` (SQLite path), `IOT_HOST` (default 0.0.0.0), `IOT_DASH_USER` (default `admin`), `IOT_TLS_CERT` / `IOT_TLS_KEY` (serve HTTPS), `IOT_ALLOW_OPEN_DASHBOARD=1` (skip dashboard login; throwaway local demo only).

### Enabling TLS (optional, recommended)

```powershell
# self-signed cert valid for the laptop's IP (replace 192.168.1.50)
openssl req -x509 -newkey rsa:2048 -nodes -keyout server/key.pem -out server/cert.pem -days 365 `
  -subj "/CN=iot-server" -addext "subjectAltName=IP:192.168.1.50"
$env:IOT_TLS_CERT = "server/cert.pem"; $env:IOT_TLS_KEY = "server/key.pem"
```

Then set `SERVER_URL` to `https://192.168.1.50:8000/api/readings` and paste `cert.pem` into `SERVER_CA_CERT` in `secrets.h`. The firmware pins that certificate and never disables verification. Keep `key.pem` out of git (add `*.pem` to `.gitignore`, already done).

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
| `POST ... -> 409` | Replayed or out-of-order `seq` for this boot (normal if you re-send a captured message). |
| `POST ... -> -2` | `https://` URL but no `SERVER_CA_CERT` in `secrets.h`. |
| Firmware prints `FATAL: SHARED_KEY ...` | You left the placeholder key in `secrets.h`. |
| `POST ... -> 422` | Reading outside physical range, so likely a bad sensor. |
| Dashboard shows STALE | No reading for over 30 s. Check the board and server log. |
| Pressure far from ~1000 hPa | Fine at altitude; a clone may differ slightly. Values outside 300 to 1100 hPa are rejected. |

## Test without hardware

```powershell
$env:IOT_SHARED_KEY = "a-demo-key-0123456789abcdef"; $env:IOT_DASH_PASSWORD = "demo-dashboard-pw"
python server/server.py                                              # terminal 1
python tools/fake_device.py --count 20 --interval 1                  # terminal 2: expect HTTP 200
python tools/fake_device.py --count 1 --bad-signature                # expect HTTP 401
python tools/fake_device.py --count 2 --interval 0 --replay          # each replay: HTTP 409
```

## Security decisions (for the Security Code Review)

Mapped to the course checklist:

| Checklist item | Status | Where |
|---|---|---|
| Default credentials | **Mitigated.** No shared defaults: the key and dashboard password are per-deployment. The server refuses to start with a key under 16 chars, a known placeholder, or no dashboard password; the firmware halts on a placeholder/short `SHARED_KEY`. | `get_key()`, `check_dashboard_auth_config()` in `server.py`; `setup()` in `main.cpp` |
| Plaintext traffic | **Mitigated when TLS is enabled** (TLS 1.2+, firmware pins the server cert, no `setInsecure()`). Plain HTTP still works for bring-up and the server prints a warning. | `main()` in `server.py`; `postReading()` in `main.cpp` |
| Unauthenticated commands | **Mitigated.** The only write path is HMAC-signed `POST /api/readings`. Replays are rejected (per-boot `boot_id` plus strictly increasing `seq`, HTTP 409). Reads need Basic auth. No endpoint sends commands to the device, and the device opens no listening port. | `do_POST`, `_dash_authorized` in `server.py` |
| Physical access | **Partly addressed, documented.** The HMAC key is in flash and the UART/JTAG is open, so someone holding the board can extract the key. Not enabled: ESP32 flash encryption and secure boot (they would stop key extraction by flash dump). Planned: ATECC608A (Lab 6) so the key never leaves the chip. Blast radius is limited to forging readings for this deployment. | roadmap |
| Unsigned updates | **N/A today:** there is no OTA or remote update path; firmware changes need a USB flash. If OTA is added it must verify a signature (secure boot v2) before applying. Library versions are pinned with `^` ranges in `platformio.ini`. | `platformio.ini` |

Other controls:

- **No credentials in the repo.** Wi-Fi password and shared key live in `firmware/include/secrets.h` (git-ignored); the server reads its secrets from environment variables. `secrets.h.example` has placeholders only.
- **Input validation.** Body size limit, JSON schema check, `boot_id` format, physical range limits; SQL uses bound parameters. Dashboard renders server data with `textContent`/numbers only, and responses carry CSP, `nosniff` and `X-Frame-Options`.
- **Constant-time comparison** for the HMAC and dashboard credentials.

Known gaps (documented honestly):

- Without TLS, readings are visible on the LAN, and the dashboard password (HTTP Basic) is sent in the clear. Use TLS on anything but a trusted network.
- Replay protection is ordering-based, not time-based: a message can be delayed or dropped by an on-path attacker, but not re-sent. The server database is the replay state (deleting it re-opens a replay window for old boots).
- No rate limiting or lockout on failed auth attempts.
- The HMAC key is a symmetric key stored in flash (see Physical access above).
- Not yet done: persistent buffering while the server is down, the 72-hour reliability run, and logging gaps to explain them. The `seq` counter and dashboard "missing messages" figure are the first step.
