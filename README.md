# GhostWire_ESP8266

## Overview

GhostWire_ESP8266 is a dual-server secure communication demo built for the ESP8266 platform. It implements:

- Diffie-Hellman handshake for establishing shared AES keys.
- AES-128 CBC encryption combined with HMAC-SHA256 authentication.
- Dual HTTP servers representing two users (`User A` and `User B`).
- JSON-based API endpoints for handshake, encryption, and decryption.

This project is designed as an information security class project demonstrating key exchange, authenticated encryption, and embedded web server communication on ESP8266.

## Architecture

The project is split into three main parts:

1. `src/main.cpp`
   - Configures Wi-Fi and static IP networking.
   - Runs two independent web servers:
     - `serverA` on port `80`
     - `serverB` on port `81`
   - Provides CORS-enabled routes for status, handshake, peer setting, encryption, and decryption.
   - Uses a shared session model where each user gets a 16-byte AES key from the handshake.

2. `lib/Diffie-Hellman Handshake/ghost_handshake.h`
   - Exposes the handshake API:
     - `Handshake_Initialize(userId)`
     - `Handshake_GetMyPublicKey(userId)`
     - `Handshake_ComputeAESKey(userId, peerPublicKey)`
   - Produces a per-user 16-byte AES session key.

3. `lib/AES-128 CBC/ghost_crypto.h` / `src/ghost_crypto.cpp`
   - Implements AES-128 block cipher and CBC mode.
   - Adds PKCS#7 padding and authenticated encryption via encrypt-then-MAC.
   - Provides Base64-safe encryption/decryption routines for API payloads.

## Features

- Dual user simulation on a single ESP8266 device.
- Diffie-Hellman shared secret establishment.
- AES-128 CBC encryption with HMAC-SHA256 authentication.
- Safe Base64 decode implementation and tamper detection.
- EEPROM-backed master key storage with validity checks.
- LED status indicators for encryption, decryption, and connectivity.

## Dependencies

- `platformio` for build and upload.
- `ArduinoJson` library.
- `ESP8266WiFi` and `ESP8266WebServer`.
- ESP8266 Arduino framework.

## Setup

1. Open the project with PlatformIO.
2. Ensure `platformio.ini` contains:
   ```ini
   build_flags = -fexceptions
   platform = espressif8266
   board = nodemcuv2
   framework = arduino
   monitor_speed = 115200
   lib_deps = bblanchon/ArduinoJson
   ```
3. Update Wi-Fi credentials in `src/main.cpp`:
   ```cpp
   const char* ssid = "Semo";
   const char* password = "01010326655";
   ```
4. Verify static IP configuration if needed.

## Build & Upload

Use PlatformIO:

```bash
platformio run --target upload
```

Then open the serial monitor at `115200` baud.

## API Endpoints

Each user has the same route structure on separate ports.

### Status

- `GET /status`
- Response: `{ "status":"Online - User A" }` or `User B`

### Handshake

- `GET /handshake`
- Returns a JSON object with `publicKey`.
- Example:
  ```json
  { "publicKey": "123456789" }
  ```

### Set Peer

- `POST /set_peer`
- Body JSON must include `peerKey`.
- Example:
  ```json
  { "peerKey": "987654321" }
  ```
- This computes the shared AES key for the session.

### Encrypt

- `POST /encrypt`
- Body JSON must include `text`.
- Returns:
  ```json
  { "cipher": "...base64..." }
  ```

### Decrypt

- `POST /decrypt`
- Body JSON must include `cipher`.
- Example:
  ```json
  { "cipher": "...base64..." }
  ```
- Returns decrypted text or a failure response if integrity checks fail.

## Security Notes

- The implementation uses AES-128 CBC + HMAC-SHA256 in encrypt-then-MAC mode.
- The shared AES key is expanded into a 48-byte master key for the crypto library.
- `Crypto_DecryptSecureBase64()` returns an empty plaintext if tampering or bad input is detected.
- `build_flags = -fexceptions` is required for exception-based error handling during decryption.

## Project Structure

```text
platformio.ini
README.md
src/
  main.cpp
  ghost_crypto.cpp
lib/
  AES-128 CBC/
    ghost_crypto.h
  Diffie-Hellman Handshake/
    ghost_handshake.h
``` 

## Notes

- This repository is primarily educational and demonstrates an embedded secure communication pattern rather than a production-ready cryptosystem.
- For production, use audited crypto libraries and avoid custom AES/handshake implementations where possible.
