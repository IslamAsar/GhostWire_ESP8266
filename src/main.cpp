#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ArduinoJson.h>
#include "../lib/Diffie-Hellman Handshake/ghost_handshake.h" 
#include "../lib/AES-128 CBC/ghost_crypto.h"    

// --- Network Credentials ---
const char* ssid = "Semo"; 
const char* password = "01010326655";

// --- Static IP Configuration ---
IPAddress local_IP(10, 61, 2, 50);
IPAddress gateway(10, 61, 2, 65);
IPAddress subnet(255, 255, 255, 0);

bool wasConnected = true; 
unsigned long lastDotTime = 0; 

// ==============================================================================
// DUAL SECURITY STATE (Adapted for Global Handshake)
// ==============================================================================
// Instead of DH objects, we just store the final 16-byte keys separately.
std::array<uint8_t, 16> sessionKeyA;
std::array<uint8_t, 16> sessionKeyB;

bool sessionReadyA = false;
bool sessionReadyB = false;

// Servers
ESP8266WebServer serverA(80);
ESP8266WebServer serverB(81);

// LEDs
#define LED_STATUS  LED_BUILTIN 
#define LED_ENCRYPT 12 
#define LED_DECRYPT 13 

int brightness = 0;
int fadeAmount = 5;
unsigned long lastFadeTime = 0;

void addCORS(ESP8266WebServer& server) {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
}

// ==============================================================================
// SHARED ROUTE LOGIC
// ==============================================================================

void processStatus(ESP8266WebServer& server, const char* userName) {
  addCORS(server);
  String response = String("{\"status\":\"Online - ") + userName + "\"}";
  server.send(200, "application/json", response);
}

void processHandshake(ESP8266WebServer& server, uint8_t userId, const char* userName) {
  addCORS(server);
  uint64_t myPubKey = Handshake_GetMyPublicKey(userId); // Use the specific user's ID
  
  Serial.printf("[DH] %s generated Unique Public Key -> %llu\n", userName, myPubKey);

  JsonDocument doc;
  doc["publicKey"] = String(myPubKey); 
  String response;
  serializeJson(doc, response);
  server.send(200, "application/json", response);
}

void processSetPeer(ESP8266WebServer& server, uint8_t userId, std::array<uint8_t, 16>& userSessionKey, bool& readyFlag, const char* userName) {
  addCORS(server);
  if (!server.hasArg("plain")) return;
  
  JsonDocument doc;
  deserializeJson(doc, server.arg("plain"));
  uint64_t peerPubKey = strtoull(doc["peerKey"].as<String>().c_str(), nullptr, 10);

  // Pass the userId into the math engine
  userSessionKey = Handshake_ComputeAESKey(userId, peerPubKey);
  readyFlag = true;
  
Serial.printf("[DEBUG] %s Shared Secret (AES Key): ", userName);
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02X ", userSessionKey[i]); // Prints each byte as a 2-digit Hex value
  }
  Serial.println(); // Print a newline at the end
    server.send(200, "application/json", "{\"status\":\"Secure Session Ready\"}");
}

// --- THE KEY EXPANDER ---
// Stretches the 16-byte DH key into the 48-bytes expected by Abkar's engine
void loadExpandedKey(std::array<uint8_t, 16>& baseKey) {
  uint8_t expandedKey[48];
  
  // 1. The first 16 bytes are the exact AES Key
  memcpy(expandedKey, baseKey.data(), 16);
  
  // 2. Abkar needs 32 bytes for the HMAC key. 
  // We simply repeat the 16-byte key twice to fill this space deterministically.
  memcpy(expandedKey + 16, baseKey.data(), 16);
  memcpy(expandedKey + 32, baseKey.data(), 16);
  
  // Now we safely load the full 48 bytes
  GhostCrypto::Crypto_SetKey(expandedKey);
}

void processEncrypt(ESP8266WebServer& server, std::array<uint8_t, 16>& userSessionKey, bool readyFlag, const char* userName) {
  addCORS(server);
  if (!readyFlag) { server.send(401, "application/json", "{\"error\":\"Handshake first\"}"); return; }

  digitalWrite(LED_ENCRYPT, HIGH);
  JsonDocument incoming;
  deserializeJson(incoming, server.arg("plain"));
  std::string plaintext = incoming["text"].as<std::string>();

  // CRITICAL INJECTION: Load the EXPANDED key
  loadExpandedKey(userSessionKey);
  std::string cipher = GhostCrypto::Crypto_EncryptSecureBase64(plaintext);

  JsonDocument outgoing;
  outgoing["cipher"] = cipher.c_str();
  String response;
  serializeJson(outgoing, response);
  server.send(200, "application/json", response);
  digitalWrite(LED_ENCRYPT, LOW);
  
  Serial.printf("[AES] Encryption success for %s\n", userName);
}

void processDecrypt(ESP8266WebServer& server, std::array<uint8_t, 16>& userSessionKey, bool readyFlag, const char* userName) {
  addCORS(server);
  if (!readyFlag) { server.send(401, "application/json", "{\"error\":\"Handshake first\"}"); return; }

  digitalWrite(LED_DECRYPT, HIGH);

  String payload = server.arg("plain");

  JsonDocument incoming;
  DeserializationError err = deserializeJson(incoming, payload);
  if (err) {
    Serial.print("          JSON Error: ");
    Serial.println(err.c_str());
    server.send(400, "application/json", "{\"error\":\"Bad JSON\"}");
    digitalWrite(LED_DECRYPT, LOW);
    return;
  }

  if (incoming["cipher"].isNull()) { 
    server.send(400, "application/json", "{\"error\":\"Missing cipher\"}"); 
    digitalWrite(LED_DECRYPT, LOW); 
    return; 
  }

  String sealedData = incoming["cipher"].as<String>();
  sealedData.trim();
  sealedData.replace(" ", "+"); 

  // CRITICAL INJECTION: Load the EXPANDED key
  loadExpandedKey(userSessionKey);
  
  // Attempt decryption
  std::string plain = GhostCrypto::Crypto_DecryptSecureBase64(sealedData.c_str());
  
  // Check if it failed
  if (plain == "") {
    Serial.printf("[SECURITY] %s Rejected Data: Integrity Check Failed or Bad Base64.\n", userName);
    server.send(400, "application/json", "{\"error\":\"Invalid Cipher / Tampering\"}");
    digitalWrite(LED_DECRYPT, LOW);
    return;
  }

  // Success!
  JsonDocument outgoing;
  outgoing["text"] = plain.c_str();
  String response;
  serializeJson(outgoing, response);
  server.send(200, "application/json", response);
  
  Serial.printf("[AES] Decryption success for %s\n", userName);
  digitalWrite(LED_DECRYPT, LOW);
}

// ==============================================================================
// ROUTE BINDINGS
// ==============================================================================

// USER A (Port 80)
void handleStatusA()    { processStatus(serverA, "User A"); }
void handleHandshakeA() { processHandshake(serverA, 0, "User A"); }
void handleSetPeerA()   { processSetPeer(serverA, 0, sessionKeyA, sessionReadyA, "User A"); }
void handleEncryptA()   { processEncrypt(serverA, sessionKeyA, sessionReadyA, "User A"); }
void handleDecryptA()   { processDecrypt(serverA, sessionKeyA, sessionReadyA, "User A"); }
void handleOptionsA()   { addCORS(serverA); serverA.send(204); }

// USER B (Port 81)
void handleStatusB()    { processStatus(serverB, "User B"); }
void handleHandshakeB() { processHandshake(serverB, 1, "User B"); }
void handleSetPeerB()   { processSetPeer(serverB, 1, sessionKeyB, sessionReadyB, "User B"); }
void handleEncryptB()   { processEncrypt(serverB, sessionKeyB, sessionReadyB, "User B"); }
void handleDecryptB()   { processDecrypt(serverB, sessionKeyB, sessionReadyB, "User B"); }
void handleOptionsB()   { addCORS(serverB); serverB.send(204); }

// ==============================================================================
// SETUP & LOOP
// ==============================================================================

void setup() {
  Serial.begin(115200);
  pinMode(LED_ENCRYPT, OUTPUT);
  pinMode(LED_DECRYPT, OUTPUT);
  pinMode(LED_STATUS, OUTPUT);

  if (!WiFi.config(local_IP, gateway, subnet)) Serial.println("[Phase] Network: Static IP Failed.");
  WiFi.begin(ssid, password);

  // Initialize unique keys for User A (0) and User B (1)
  Handshake_Initialize(0); 
  Handshake_Initialize(1);

  // User A Routes
  serverA.on("/status", HTTP_GET, handleStatusA);
  serverA.on("/handshake", HTTP_GET, handleHandshakeA);
  serverA.on("/set_peer", HTTP_POST, handleSetPeerA);
  serverA.on("/encrypt", HTTP_POST, handleEncryptA);
  serverA.on("/decrypt", HTTP_POST, handleDecryptA);
  serverA.on("/set_peer", HTTP_OPTIONS, handleOptionsA);
  serverA.on("/encrypt", HTTP_OPTIONS, handleOptionsA);
  serverA.on("/decrypt", HTTP_OPTIONS, handleOptionsA);
  serverA.on("/handshake", HTTP_OPTIONS, handleOptionsA);

  // User B Routes
  serverB.on("/status", HTTP_GET, handleStatusB);
  serverB.on("/handshake", HTTP_GET, handleHandshakeB);
  serverB.on("/set_peer", HTTP_POST, handleSetPeerB);
  serverB.on("/encrypt", HTTP_POST, handleEncryptB);
  serverB.on("/decrypt", HTTP_POST, handleDecryptB);
  serverB.on("/set_peer", HTTP_OPTIONS, handleOptionsB);
  serverB.on("/encrypt", HTTP_OPTIONS, handleOptionsB);
  serverB.on("/decrypt", HTTP_OPTIONS, handleOptionsB);
  serverB.on("/handshake", HTTP_OPTIONS, handleOptionsB);

  serverA.begin();
  serverB.begin();
}

void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    if (!wasConnected) {
      Serial.println(" SUCCESS!");
      Serial.printf("[Phase] Network: Dual HSM Servers online at IP -> %s\n", WiFi.localIP().toString().c_str());
      wasConnected = true; 
    }

    serverA.handleClient();
    serverB.handleClient();

    if (millis() - lastFadeTime > 30) {
      analogWrite(LED_STATUS, brightness);
      brightness = brightness + fadeAmount;
      if (brightness <= 0 || brightness >= 255) fadeAmount = -fadeAmount;
      lastFadeTime = millis();
    }
  } 
  else {
    if (wasConnected) {
      Serial.print("[Phase] Warning: Connection Lost. Waiting");
      wasConnected = false; 
      WiFi.begin(ssid, password); 
    }
    digitalWrite(LED_STATUS, (millis() / 150) % 2); 
    if (millis() - lastDotTime > 1000) { Serial.print("."); lastDotTime = millis(); }
  }
}