// !!! IMPORTANT: ESP8266 Arduino builds do NOT enable exceptions by default.
// You MUST add -fexceptions to your build flags, otherwise any decryption
// failure will crash the device with a reset.
// In platformio.ini:
//   build_flags = -fexceptions
// In Arduino IDE you may need to use PlatformIO or add the flag manually.

#if !defined(__EXCEPTIONS) && !defined(ESP_PLATFORM)
#error "GhostCrypto requires exceptions to be enabled. Add -fexceptions to your build flags."
#endif

#include "ghost_crypto.h"
#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <cstdlib>
#include <EEPROM.h>

namespace GhostCrypto {

// ============== Secure memory wipe ==============
static void secure_wipe(void* ptr, size_t len) {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

// ============== Constant‑time comparison ==============
static bool constant_time_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// ============== ESP8266 hardware random number generator ==============
static void hw_fill_random(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = *(volatile uint32_t*)0x3FF20E44;
        size_t copy = (i + 4 <= len) ? 4 : (len - i);
        memcpy(buf + i, &r, copy);
    }
}

// ============== AES S‑Box (FIPS‑197) – stored in Flash (PROGMEM) ==============
static const uint8_t sbox[256] PROGMEM = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] PROGMEM = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t Rcon[11] PROGMEM = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Helper to read a byte from Flash
static inline uint8_t pgm_byte(const uint8_t* ptr) {
    return pgm_read_byte(ptr);
}

// ============== Galois Field (2^8) operations ==============
inline uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) result ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return result;
}

// ============== State matrix helpers ==============
using State = uint8_t[4][4];

inline void bytesToState(const uint8_t* in, State s) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = in[r + 4*c];
}

inline void stateToBytes(const State s, uint8_t* out) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            out[r + 4*c] = s[r][c];
}

void SubBytes(State s) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = pgm_byte(&sbox[s[r][c]]);
}

void InvSubBytes(State s) {
    for (int r = 0; r < 4; ++r)
        for (int c = 0; c < 4; ++c)
            s[r][c] = pgm_byte(&inv_sbox[s[r][c]]);
}

void ShiftRows(State s) {
    uint8_t t;
    t = s[1][0]; s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = t;
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
    t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
    t = s[3][3]; s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = t;
}

void InvShiftRows(State s) {
    uint8_t t;
    t = s[1][3]; s[1][3] = s[1][2]; s[1][2] = s[1][1]; s[1][1] = s[1][0]; s[1][0] = t;
    t = s[2][0]; s[2][0] = s[2][2]; s[2][2] = t;
    t = s[2][1]; s[2][1] = s[2][3]; s[2][3] = t;
    t = s[3][0]; s[3][0] = s[3][1]; s[3][1] = s[3][2]; s[3][2] = s[3][3]; s[3][3] = t;
}

void MixColumns(State s) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a = s[0][c], b = s[1][c], d = s[2][c], e = s[3][c];
        s[0][c] = xtime(a) ^ xtime(b) ^ b ^ d ^ e;
        s[1][c] = a ^ xtime(b) ^ xtime(d) ^ d ^ e;
        s[2][c] = a ^ b ^ xtime(d) ^ xtime(e) ^ e;
        s[3][c] = xtime(a) ^ a ^ b ^ d ^ xtime(e);
    }
}

void InvMixColumns(State s) {
    for (int c = 0; c < 4; ++c) {
        uint8_t a = s[0][c], b = s[1][c], d = s[2][c], e = s[3][c];
        s[0][c] = gf_mult(a,0x0e) ^ gf_mult(b,0x0b) ^ gf_mult(d,0x0d) ^ gf_mult(e,0x09);
        s[1][c] = gf_mult(a,0x09) ^ gf_mult(b,0x0e) ^ gf_mult(d,0x0b) ^ gf_mult(e,0x0d);
        s[2][c] = gf_mult(a,0x0d) ^ gf_mult(b,0x09) ^ gf_mult(d,0x0e) ^ gf_mult(e,0x0b);
        s[3][c] = gf_mult(a,0x0b) ^ gf_mult(b,0x0d) ^ gf_mult(d,0x09) ^ gf_mult(e,0x0e);
    }
}

void AddRoundKey(State s, const uint8_t* rk) {
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r)
            s[r][c] ^= rk[r + 4*c];
}

// ============== Key Expansion ==============
void KeyExpansion(const uint8_t* key, uint8_t* roundKeys) {
    std::memcpy(roundKeys, key, 16);
    int i = 16;
    while (i < 176) {
        uint8_t temp[4];
        std::memcpy(temp, roundKeys + i - 4, 4);
        if (i % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = t;
            for (int k = 0; k < 4; ++k) temp[k] = pgm_byte(&sbox[temp[k]]);
            temp[0] ^= pgm_byte(&Rcon[i/16]);
        }
        for (int k = 0; k < 4; ++k) {
            roundKeys[i] = roundKeys[i-16] ^ temp[k];
            ++i;
        }
    }
}

// ============== AES block encrypt / decrypt ==============
void AES128_EncryptBlock(const uint8_t* in, const uint8_t* rk, uint8_t* out) {
    State state;
    bytesToState(in, state);
    AddRoundKey(state, rk);
    for (int round = 1; round <= 9; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, rk + round * 16);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, rk + 160);
    stateToBytes(state, out);
}

void AES128_DecryptBlock(const uint8_t* in, const uint8_t* rk, uint8_t* out) {
    State state;
    bytesToState(in, state);
    AddRoundKey(state, rk + 160);
    for (int round = 9; round >= 1; --round) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, rk + round * 16);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, rk);
    stateToBytes(state, out);
}

// ============== PKCS#7 Padding ==============
static std::vector<uint8_t> pkcs7_pad(const std::string& data) {
    size_t len = data.size();
    size_t pad = 16 - (len % 16);
    if (pad == 0) pad = 16;
    std::vector<uint8_t> padded(len + pad);
    std::copy(data.begin(), data.end(), padded.begin());
    std::fill(padded.begin() + len, padded.end(), static_cast<uint8_t>(pad));
    return padded;
}

static std::string pkcs7_unpad(const std::vector<uint8_t>& data) {
    if (data.empty() || data.size() % 16 != 0)
        throw std::runtime_error("Integrity check failed");
    uint8_t pad = data.back();
    if (pad == 0 || pad > 16) throw std::runtime_error("Integrity check failed");
    if (pad > data.size()) throw std::runtime_error("Integrity check failed");
    size_t start = data.size() - pad;
    for (size_t i = start; i < data.size(); ++i)
        if (data[i] != pad) throw std::runtime_error("Integrity check failed");
    return std::string(data.begin(), data.begin() + start);
}

// ============== Helper: random IV ==============
static std::string generateRandomIV() {
    std::string iv(16, '\0');
    hw_fill_random(reinterpret_cast<uint8_t*>(&iv[0]), 16);
    return iv;
}

// ============== Hex conversion (heap usage remains; acceptable for now) ==============
static std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i) oss << std::setw(2) << static_cast<int>(data[i]);
    return oss.str();
}

static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("Integrity check failed");
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        char* end = nullptr;
        unsigned long val = std::strtoul(byte_str.c_str(), &end, 16);
        if (end != byte_str.c_str() + 2) throw std::runtime_error("Integrity check failed");
        bytes.push_back(static_cast<uint8_t>(val));
    }
    return bytes;
}

// ============== Base64 conversion ==============
static const char kBase64Alphabet[] PROGMEM = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string safe_base64_encode(const uint8_t* data, size_t len) {
    std::string encoded;
    encoded.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16);
        if (i + 1 < len) triple |= (static_cast<uint32_t>(data[i + 1]) << 8);
        if (i + 2 < len) triple |= data[i + 2];
        encoded.push_back(static_cast<char>(pgm_read_byte(&kBase64Alphabet[(triple >> 18) & 0x3F])));
        encoded.push_back(static_cast<char>(pgm_read_byte(&kBase64Alphabet[(triple >> 12) & 0x3F])));
        encoded.push_back((i + 1 < len) ? static_cast<char>(pgm_read_byte(&kBase64Alphabet[(triple >> 6) & 0x3F])) : '=');
        encoded.push_back((i + 2 < len) ? static_cast<char>(pgm_read_byte(&kBase64Alphabet[triple & 0x3F])) : '=');
    }
    return encoded;
}

std::vector<uint8_t> safe_base64_decode(const std::string &in) {
    std::vector<uint8_t> out;
    if (in.empty()) return out;

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (uint8_t c : in) {
        if (T[c] == -1) {
            if (c == '=' || c == ' ' || c == '\n' || c == '\r') continue; // Ignore padding and safe whitespace
            return {}; // ILLEGAL CHARACTER: Abort instantly, return empty
        }
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(uint8_t((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// ============== SHA‑256 implementation (K in PROGMEM) ==============
static const uint32_t K[64] PROGMEM = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

struct SHA256_CTX {
    uint8_t  buffer[64];
    uint32_t state[8];
    uint64_t count;
};

static void sha256_init(SHA256_CTX* ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define CH(x,y,z)   ((x & y) ^ (~x & z))
#define MAJ(x,y,z)  ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x)      (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)      (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x)     (ROTR(x,7) ^ ROTR(x,18) ^ (x >> 3))
#define SIG1(x)     (ROTR(x,17) ^ ROTR(x,19) ^ (x >> 10))

static void sha256_transform(SHA256_CTX* ctx) {
    uint32_t W[64];
    for (int i = 0; i < 16; i++) {
        W[i] = (ctx->buffer[i*4] << 24) | (ctx->buffer[i*4+1] << 16) |
               (ctx->buffer[i*4+2] << 8) | ctx->buffer[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e,f,g) + pgm_read_dword(&K[i]) + W[i];
        uint32_t t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_update(SHA256_CTX* ctx, const uint8_t* data, size_t len) {
    size_t i = ctx->count % 64;
    ctx->count += len;
    while (len--) {
        ctx->buffer[i++] = *data++;
        if (i == 64) {
            sha256_transform(ctx);
            i = 0;
        }
    }
}

static void sha256_final(SHA256_CTX* ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    int padLen = (ctx->count % 64 < 56) ? (56 - ctx->count % 64) : (120 - ctx->count % 64);
    uint8_t padding[128] = {0x80};
    sha256_update(ctx, padding, padLen);
    uint8_t bits_be[8];
    for (int i = 0; i < 8; i++) bits_be[i] = (bits >> (56 - 8*i)) & 0xFF;
    sha256_update(ctx, bits_be, 8);
    for (int i = 0; i < 32; i++) digest[i] = (ctx->state[i/4] >> (24 - 8*(i%4))) & 0xFF;
    // Wipe the context thoroughly
    secure_wipe(ctx, sizeof(SHA256_CTX));
}

static void hmac_sha256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t mac[32]) {
    uint8_t key_block[64];
    memset(key_block, 0, 64);
    if (key_len > 64) {
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_block);   // final wipes ctx
        key_len = 32;
    } else {
        memcpy(key_block, key, key_len);
    }
    uint8_t o_key_pad[64], i_key_pad[64];
    for (int i = 0; i < 64; i++) {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, i_key_pad, 64);
    sha256_update(&ctx, data, data_len);
    uint8_t inner[32];
    sha256_final(&ctx, inner);    // final wipes ctx

    sha256_init(&ctx);
    sha256_update(&ctx, o_key_pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);      // final wipes ctx

    secure_wipe(key_block, sizeof(key_block));
    secure_wipe(i_key_pad, sizeof(i_key_pad));
    secure_wipe(o_key_pad, sizeof(o_key_pad));
    secure_wipe(inner, sizeof(inner));
}

// ============== Master key storage (EEPROM, improved validity check) ==============
#define EEPROM_SIZE 64
static uint8_t g_masterKey[48] = {0};
static bool g_keyLoaded = false;

static bool load_key_from_eeprom() {
    EEPROM.begin(EEPROM_SIZE);
    uint8_t buf[48];
    EEPROM.get(0, buf);
    EEPROM.end();

    // Reject both all‑zero and all‑0xFF (uninitialised EEPROM)
    uint8_t orSum = 0, andSum = 0xFF;
    for (int i = 0; i < 48; i++) {
        orSum |= buf[i];
        andSum &= buf[i];
    }
    if (orSum == 0 || andSum == 0xFF) return false;

    memcpy(g_masterKey, buf, 48);
    return true;
}

static bool save_key_to_eeprom() {
    EEPROM.begin(EEPROM_SIZE);
    EEPROM.put(0, g_masterKey);
    bool ok = EEPROM.commit();
    EEPROM.end();
    return ok;
}

static void init_key() {
    if (g_keyLoaded) return;
    if (load_key_from_eeprom()) {
        g_keyLoaded = true;
        return;
    }
    // No valid key found: generate a new random key and store it
    hw_fill_random(g_masterKey, 48);
    if (save_key_to_eeprom()) {
        g_keyLoaded = true;
    } else {
        // EEPROM commit failed, but the device will still work (volatile key only)
        g_keyLoaded = true;
    }
}

bool Crypto_SetKey(const uint8_t* key) {
    if (key == nullptr) return false;
    secure_wipe(g_masterKey, 48);
    std::memcpy(g_masterKey, key, 48);
    g_keyLoaded = true;
    return true;
}

bool Crypto_GenerateNewKey() {
    secure_wipe(g_masterKey, 48);
    hw_fill_random(g_masterKey, 48);
    bool ok = save_key_to_eeprom();
    g_keyLoaded = ok;
    return ok;
}

// ============== Internal CBC (with secure wipe) ==============
static std::vector<uint8_t> cbc_encrypt(const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& plain) {
    init_key();
    uint8_t rk[176];
    KeyExpansion(g_masterKey, rk);
    std::vector<uint8_t> padded = pkcs7_pad(std::string(plain.begin(), plain.end()));
    std::vector<uint8_t> ct(padded.size());
    uint8_t prev[16];
    std::copy(iv.begin(), iv.end(), prev);
    uint8_t* ct_ptr = ct.data();

    uint8_t block[16];
    for (size_t i = 0; i < padded.size(); i += 16) {
        for (int j = 0; j < 16; ++j) block[j] = padded[i+j] ^ prev[j];
        AES128_EncryptBlock(block, rk, prev);
        std::copy(prev, prev+16, ct_ptr + i);
    }

    secure_wipe(rk,    sizeof(rk));
    secure_wipe(block, sizeof(block));
    secure_wipe(prev,  sizeof(prev));
    return ct;
}

static std::vector<uint8_t> cbc_decrypt(const std::vector<uint8_t>& iv,
                                        const std::vector<uint8_t>& ct) {
    init_key();
    uint8_t rk[176];
    KeyExpansion(g_masterKey, rk);
    std::vector<uint8_t> plain(ct.size());
    uint8_t prev[16];
    std::copy(iv.begin(), iv.end(), prev);
    const uint8_t* ct_data = ct.data();
    uint8_t* plain_data = plain.data();

    uint8_t decrypted[16];
    for (size_t i = 0; i < ct.size(); i += 16) {
        AES128_DecryptBlock(ct_data + i, rk, decrypted);
        for (int j = 0; j < 16; ++j) decrypted[j] ^= prev[j];
        std::copy(decrypted, decrypted+16, plain_data + i);
        std::copy(ct_data + i, ct_data + i + 16, prev);
    }

    secure_wipe(rk,        sizeof(rk));
    secure_wipe(decrypted, sizeof(decrypted));
    secure_wipe(prev,      sizeof(prev));
    return plain;
}

static std::string aes_decrypt_cbc_and_unpad(const std::vector<uint8_t>& ct, const std::vector<uint8_t>& iv, const uint8_t* key) {
    try {
        auto plain = cbc_decrypt(iv, ct);
        return pkcs7_unpad(plain);
    } catch (const std::runtime_error&) {
        return "";
    }
}

// ============== SECURE API (Encrypt-then-MAC) ==============
std::string Crypto_EncryptSecure(const std::string& plaintext) {
    init_key();
    std::string ivBin = generateRandomIV();
    std::vector<uint8_t> iv(ivBin.begin(), ivBin.end());
    auto ct = cbc_encrypt(iv, std::vector<uint8_t>(plaintext.begin(), plaintext.end()));

    std::vector<uint8_t> ivct = iv;
    ivct.insert(ivct.end(), ct.begin(), ct.end());
    uint8_t mac[32];
    hmac_sha256(g_masterKey + 16, 32, ivct.data(), ivct.size(), mac);

    std::string sealed = bytesToHex(iv.data(), 16) + ":" +
                         bytesToHex(ct.data(), ct.size()) + ":" +
                         bytesToHex(mac, 32);
    secure_wipe(mac, sizeof(mac));
    return sealed;
}

std::string Crypto_DecryptSecure(const std::string& sealedData) {
    init_key();
    size_t p1 = sealedData.find(':');
    size_t p2 = sealedData.find(':', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos)
        throw std::runtime_error("Integrity check failed");

    auto iv  = hexToBytes(sealedData.substr(0, p1));
    auto ct  = hexToBytes(sealedData.substr(p1 + 1, p2 - p1 - 1));
    auto mac = hexToBytes(sealedData.substr(p2 + 1));

    if (iv.size() != 16 || ct.size() % 16 != 0 || mac.size() != 32)
        throw std::runtime_error("Integrity check failed");

    std::vector<uint8_t> ivct = iv;
    ivct.insert(ivct.end(), ct.begin(), ct.end());
    uint8_t expected[32];
    hmac_sha256(g_masterKey + 16, 32, ivct.data(), ivct.size(), expected);
    if (!constant_time_equal(expected, mac.data(), 32))
        throw std::runtime_error("Integrity check failed");

    auto plain = cbc_decrypt(iv, ct);
    secure_wipe(expected, sizeof(expected));
    return pkcs7_unpad(plain);
}

std::string Crypto_EncryptSecureBase64(const std::string& plaintext) {
    init_key();
    std::string ivBin = generateRandomIV();
    std::vector<uint8_t> iv(ivBin.begin(), ivBin.end());
    auto ct = cbc_encrypt(iv, std::vector<uint8_t>(plaintext.begin(), plaintext.end()));

    std::vector<uint8_t> ivct = iv;
    ivct.insert(ivct.end(), ct.begin(), ct.end());
    uint8_t mac[32];
    hmac_sha256(g_masterKey + 16, 32, ivct.data(), ivct.size(), mac);

    std::string sealed = safe_base64_encode(iv.data(), 16) + ":" +
                         safe_base64_encode(ct.data(), ct.size()) + ":" +
                         safe_base64_encode(mac, 32);
    secure_wipe(mac, sizeof(mac));
    return sealed;
}

std::string Crypto_DecryptSecureBase64(const std::string& sealedData) {
    // 1. FORMAT CHECK: Ensure exactly 2 colons exist before string manipulation
    int colons = 0;
    for (char c : sealedData) if (c == ':') colons++;
    if (colons != 2) return ""; // Fails safely

    // 2. SAFE EXTRACTION
    size_t p1 = sealedData.find(':');
    size_t p2 = sealedData.find(':', p1 + 1);
    
    if (p1 == std::string::npos || p2 == std::string::npos) return ""; // Fails safely

    std::string iv_str  = sealedData.substr(0, p1);
    std::string ct_str  = sealedData.substr(p1 + 1, p2 - p1 - 1);
    std::string mac_str = sealedData.substr(p2 + 1);

    // 3. SECURE DECODE: Use the bulletproof decoder
    std::vector<uint8_t> iv  = safe_base64_decode(iv_str);
    std::vector<uint8_t> ct  = safe_base64_decode(ct_str);
    std::vector<uint8_t> mac = safe_base64_decode(mac_str);

    // 4. MEMORY BOUNDS CHECK: Ensure arrays are perfectly sized before math
    if (iv.size() != 16 || ct.empty() || ct.size() % 16 != 0 || mac.size() != 32) {
        return ""; // Corrupted or truncated payload. Fail safely.
    }

    // 5. INTEGRITY CHECK (HMAC)
    std::vector<uint8_t> ivct = iv;
    ivct.insert(ivct.end(), ct.begin(), ct.end());
    
    uint8_t calculated_mac[32];
    
    // (Assuming Abkar's hmac_sha256 function takes: key, key_len, data, data_len, out_buffer)
    // Adjust 'g_masterKey' below to match however Abkar globally stores the 48-byte key in this file
    hmac_sha256(g_masterKey + 16, 32, ivct.data(), ivct.size(), calculated_mac);

    // Constant-time compare to prevent timing attacks
    bool valid = true;
    for (size_t i = 0; i < 32; i++) {
        if (calculated_mac[i] != mac[i]) valid = false;
    }

    if (!valid) {
        return ""; // Signature does not match! Hacker or Wrong Key! Fail safely.
    }

    // 6. DECRYPT
    // Payload is fully authenticated and memory-safe. Proceed with AES decryption.
    std::string plaintext = aes_decrypt_cbc_and_unpad(ct, iv, g_masterKey);
    return plaintext;
}

} // namespace GhostCrypto