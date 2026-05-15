#include "ghost_handshake.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>

#include <Arduino.h>

namespace {

constexpr uint64_t P = 2305843009213693951ULL; // 2^61 - 1 (demo prime)
constexpr uint64_t G = 5ULL;
constexpr uint8_t MAX_USERS = 2; // Support Dual-Port setup

// The Multi-User State Array
struct UserState {
    uint64_t privateKey = 0;
    uint64_t publicKey = 0;
    bool initialized = false;
};

UserState g_users[MAX_USERS];

uint64_t random_u64() {
    // ESP8266: ESP.random() is the recommended source.
    // Wi-Fi should be enabled for better entropy.
    uint64_t hi = static_cast<uint64_t>(ESP.random());
    uint64_t lo = static_cast<uint64_t>(ESP.random());
    return (hi << 32) ^ lo;
}

uint64_t addMod(uint64_t a, uint64_t b, uint64_t mod) {
    a %= mod;
    b %= mod;

    if (a >= mod - b) {
        return a - (mod - b);
    }
    return a + b;
}

uint64_t mulMod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t res = 0;
    a %= mod;
    while (b > 0) {
        if (b % 2 == 1) {
            res = addMod(res, a, mod);
        }
        a = addMod(a, a, mod);
        b /= 2;
    }
    return res;
}

uint64_t modExp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            res = mulMod(res, base, mod);
        }
        base = mulMod(base, base, mod);
        exp /= 2;
    }
    return res;
}

// --- SHA256 Implementation ---
class SHA256 {
private:
    uint32_t state_[8];
    uint8_t data_[64];
    uint32_t datalen_;
    uint64_t bitlen_;

    static constexpr uint32_t k_[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    uint32_t bsig0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    uint32_t bsig1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    uint32_t ssig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    uint32_t ssig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

public:
    SHA256() {
        state_[0] = 0x6a09e667;
        state_[1] = 0xbb67ae85;
        state_[2] = 0x3c6ef372;
        state_[3] = 0xa54ff53a;
        state_[4] = 0x510e527f;
        state_[5] = 0x9b05688c;
        state_[6] = 0x1f83d9ab;
        state_[7] = 0x5be0cd19;
        datalen_ = 0;
        bitlen_ = 0;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            data_[datalen_] = data[i];
            datalen_++;
            if (datalen_ == 64) {
                transform();
                bitlen_ += 512;
                datalen_ = 0;
            }
        }
    }

    std::array<uint8_t, 32> final() {
        uint32_t i = datalen_;
        if (datalen_ < 56) {
            data_[i++] = 0x80;
            while (i < 56) data_[i++] = 0x00;
        } else {
            data_[i++] = 0x80;
            while (i < 64) data_[i++] = 0x00;
            transform();
            memset(data_, 0, 56);
        }
        bitlen_ += datalen_ * 8;
        data_[63] = bitlen_;
        data_[62] = bitlen_ >> 8;
        data_[61] = bitlen_ >> 16;
        data_[60] = bitlen_ >> 24;
        data_[59] = bitlen_ >> 32;
        data_[58] = bitlen_ >> 40;
        data_[57] = bitlen_ >> 48;
        data_[56] = bitlen_ >> 56;
        transform();

        std::array<uint8_t, 32> hash;
        for (i = 0; i < 4; ++i) {
            hash[i]      = (state_[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (state_[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (state_[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (state_[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (state_[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (state_[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (state_[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (state_[7] >> (24 - i * 8)) & 0x000000ff;
        }
        return hash;
    }

private:
    void transform() {
        uint32_t a, b, c, d, e, f, g, h, t1, t2, w[64];
        for (int i = 0, j = 0; i < 16; ++i, j += 4) {
            w[i] = (data_[j] << 24) | (data_[j + 1] << 16) | (data_[j + 2] << 8) | (data_[j + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
        }

        a = state_[0];
        b = state_[1];
        c = state_[2];
        d = state_[3];
        e = state_[4];
        f = state_[5];
        g = state_[6];
        h = state_[7];

        for (int i = 0; i < 64; ++i) {
            t1 = h + bsig1(e) + ch(e, f, g) + k_[i] + w[i];
            t2 = bsig0(a) + maj(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }
};

constexpr uint32_t SHA256::k_[64];

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len) {
    SHA256 s;
    s.update(data, len);
    return s.final();
}

} // namespace

// ==============================================================================
// MULTI-USER EXPORTED FUNCTIONS
// ==============================================================================

void Handshake_Initialize(uint8_t userId) {
    if (userId >= MAX_USERS) return;
    if (g_users[userId].initialized) return;

    g_users[userId].privateKey = (random_u64() % (P - 2ULL)) + 2ULL;
    g_users[userId].publicKey = modExp(G, g_users[userId].privateKey, P);
    g_users[userId].initialized = true;
}

uint64_t Handshake_GetMyPublicKey(uint8_t userId) {
    if (userId >= MAX_USERS || !g_users[userId].initialized) return 0;
    return g_users[userId].publicKey;
}

std::array<uint8_t, 16> Handshake_ComputeAESKey(uint8_t userId, uint64_t peerPublicKey) {
    std::array<uint8_t, 16> sessionKey = {0};
    if (userId >= MAX_USERS || !g_users[userId].initialized) return sessionKey;

    uint64_t sharedSecret = modExp(peerPublicKey, g_users[userId].privateKey, P);
    
    uint8_t secretBytes[8];
    for (int i = 0; i < 8; ++i) {
        secretBytes[i] = static_cast<uint8_t>((sharedSecret >> (i * 8)) & 0xFF);
    }
    std::array<uint8_t, 32> fullHash = sha256(secretBytes, 8);

    for (int i = 0; i < 16; ++i) {
        sessionKey[i] = fullHash[i];
    }
    
    return sessionKey;
}