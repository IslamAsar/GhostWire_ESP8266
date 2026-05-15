#pragma once

#include <array>
#include <cstdint>

// userId: 0 for User A, 1 for User B
void Handshake_Initialize(uint8_t userId);
uint64_t Handshake_GetMyPublicKey(uint8_t userId);
std::array<uint8_t, 16> Handshake_ComputeAESKey(uint8_t userId, uint64_t peerPublicKey);