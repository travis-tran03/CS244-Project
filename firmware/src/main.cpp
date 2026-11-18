// Vertical slice: BMP280 -> ESP32 -> Wi-Fi -> server -> dashboard.
//
// Every SAMPLE_PERIOD_MS the board reads the BMP280 (temperature in C, pressure in hPa),
// signs a small JSON message with HMAC-SHA256 and POSTs it to the server. Nothing blocks for
// long: Wi-Fi reconnects in the background and a failed POST just means the next one tries again.
//
// Indicators (Lab 1 pin map):  green LED = last POST accepted,  red LED = Wi-Fi/sensor/POST problem,
//                              yellow LED = a POST is in flight,  OLED = live values and status.
// Open the Serial Monitor at 115200 for a log line per message.

#include <Arduino.h>
#include <Wire.h>
#include <SPI.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <mbedtls/md.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Adafruit_BMP280.h>

#if __has_include("secrets.h")
#include "secrets.h"
#else
#error "Copy firmware/include/secrets.h.example to firmware/include/secrets.h and fill it in."
#endif

// ---- Lab 1 pin map ------------------------------------------------------------------------
const int LED_RED = 2, LED_YELLOW = 4, LED_GREEN = 15;
const int OLED_CS = 5, OLED_DC = 16, OLED_RST = 17;  // SCK 18, MOSI 23
const int I2C_SDA = 21, I2C_SCL = 22;

// ---- Timing --------------------------------------------------------------------------------
const uint32_t SAMPLE_PERIOD_MS = 5000;
const uint32_t WIFI_RETRY_MS    = 10000;
const uint16_t HTTP_TIMEOUT_MS  = 3000;

Adafruit_SSD1306 oled(128, 64, &SPI, OLED_DC, OLED_RST, OLED_CS);
Adafruit_BMP280 bmp(&Wire);

bool oledOk = false, bmpOk = false;
uint32_t seq = 0;                 // message counter; the dashboard uses it to spot lost messages
uint32_t lastSample = 0, lastWifiTry = 0;
bool lastPostOk = false;
int  lastHttp = 0;
float lastTemp = NAN, lastPres = NAN;

// ---- Helpers -------------------------------------------------------------------------------
// HMAC-SHA256(SHARED_KEY, msg) as 64 lowercase hex chars (+ NUL) in out.
void hmacHex(const char *msg, size_t len, char out[65]) {
  uint8_t mac[32];
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, (const uint8_t *)SHARED_KEY, strlen(SHARED_KEY), (const uint8_t *)msg, len, mac);
  for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", mac[i]);
  out[64] = 0;
}

void setLeds(bool red, bool yellow, bool green) {
  digitalWrite(LED_RED, red);
  digitalWrite(LED_YELLOW, yellow);
  digitalWrite(LED_GREEN, green);
}

void draw() {
  if (!oledOk) return;
  oled.clearDisplay();
  oled.setTextColor(SSD1306_WHITE);
  oled.setTextSize(1);
  oled.setCursor(0, 0);
  oled.print(DEVICE_ID);
  oled.setTextSize(2);
  oled.setCursor(0, 14);
  if (isnan(lastTemp)) oled.print("-- C"); else oled.printf("%.2f C", lastTemp);
  oled.setCursor(0, 34);
  if (isnan(lastPres)) oled.print("-- hPa"); else oled.printf("%.1f hPa", lastPres);
  oled.setTextSize(1);
  oled.setCursor(0, 56);
  oled.printf("WiFi:%s  POST:%s #%lu", WiFi.status() == WL_CONNECTED ? "ok" : "--",
              lastPostOk ? "ok" : (lastHttp ? String(lastHttp).c_str() : "--"), (unsigned long)seq);
  oled.display();
}

// Non-blocking Wi-Fi supervision: if the link is down, restart the connection every WIFI_RETRY_MS.
void superviseWifi() {
  if (WiFi.status() == WL_CONNECTED) return;
  uint32_t now = millis();
  if (now - lastWifiTry < WIFI_RETRY_MS && lastWifiTry != 0) return;
  lastWifiTry = now;
  Serial.println("WiFi: (re)connecting...");
  WiFi.disconnect();
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

bool initBmp() {
  // A genuine BMP280 reports chip id 0x58. Kit clones sometimes report 0x56/0x57 (samples) or
  // 0x60 (BME280, same temperature/pressure registers), so try each.
  const uint8_t ids[] = {0x58, 0x60, 0x56, 0x57};
  for (uint8_t id : ids) {
    if (bmp.begin(0x76, id)) {
      Serial.printf("BMP280: found at 0x76 (chip id 0x%02X)\n", id);
      bmp.setSampling(Adafruit_BMP280::MODE_NORMAL, Adafruit_BMP280::SAMPLING_X2,
                      Adafruit_BMP280::SAMPLING_X16, Adafruit_BMP280::FILTER_X4,
                      Adafruit_BMP280::STANDBY_MS_500);
      return true;
    }
  }
  Serial.println("BMP280: NOT FOUND at 0x76 (check SDA D21, SCL D22, CSB->3V3, SDO->GND)");
  return false;
}

// Build, sign and POST one message. Returns true when the server answered 200.
bool postReading(float tempC, float presHpa) {
  char body[200];
  int n = snprintf(body, sizeof(body),
                   "{\"device\":\"%s\",\"seq\":%lu,\"uptime_s\":%lu,\"temp_c\":%.2f,\"pressure_hpa\":%.2f,\"rssi\":%d}",
                   DEVICE_ID, (unsigned long)seq, (unsigned long)(millis() / 1000), tempC, presHpa, WiFi.RSSI());
  char sig[65];
  hmacHex(body, n, sig);

  HTTPClient http;
  http.setConnectTimeout(HTTP_TIMEOUT_MS);
  http.setTimeout(HTTP_TIMEOUT_MS);
  if (!http.begin(SERVER_URL)) { lastHttp = -1; return false; }
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Signature", sig);
  lastHttp = http.POST((uint8_t *)body, n);   // negative = transport error, else HTTP status
  http.end();
  Serial.printf("POST seq=%lu T=%.2fC P=%.2fhPa -> %d\n", (unsigned long)seq, tempC, presHpa, lastHttp);
  return lastHttp == 200;
}

// ---- Arduino -------------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n=== IoT vertical slice: BMP280 -> Wi-Fi -> server ===");

  pinMode(LED_RED, OUTPUT); pinMode(LED_YELLOW, OUTPUT); pinMode(LED_GREEN, OUTPUT);
  setLeds(true, false, false);

  SPI.begin();
  oledOk = oled.begin(SSD1306_SWITCHCAPVCC);
  if (!oledOk) Serial.println("OLED: not found (continuing without it)");

  Wire.begin(I2C_SDA, I2C_SCL);
  bmpOk = initBmp();

  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  superviseWifi();
  draw();
}

void loop() {
  superviseWifi();

  uint32_t now = millis();
  if (now - lastSample < SAMPLE_PERIOD_MS && lastSample != 0) return;
  lastSample = now;

  if (!bmpOk) bmpOk = initBmp();             // sensor may have been loose at boot: keep trying
  if (bmpOk) {
    float t = bmp.readTemperature();         // degrees C
    float p = bmp.readPressure() / 100.0f;   // Pa -> hPa
    if (isnan(t) || isnan(p) || p < 300 || p > 1100) {
      Serial.println("BMP280: bad reading, skipping");
    } else {
      lastTemp = t; lastPres = p;
      if (WiFi.status() == WL_CONNECTED) {
        setLeds(false, true, false);         // yellow: sending
        lastPostOk = postReading(t, p);
      } else {
        lastPostOk = false; lastHttp = 0;
        Serial.println("WiFi down: reading not sent");
      }
      seq++;                                 // consumed even on failure, so the server sees the gap
    }
  } else {
    lastPostOk = false;
  }
  setLeds(!lastPostOk, false, lastPostOk);
  draw();
}
