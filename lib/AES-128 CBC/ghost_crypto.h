#ifndef GHOST_CRYPTO_H
#define GHOST_CRYPTO_H

#include <string>
#include <cstdint>
#include <vector>

namespace GhostCrypto {

    // ========== Key management ==========
    bool Crypto_SetKey(const uint8_t* key);          
    bool Crypto_GenerateNewKey();                    

    // ========== SECURE production API ==========
    std::string Crypto_EncryptSecure(const std::string& plaintext);
    std::string Crypto_DecryptSecure(const std::string& sealedData);

    // Base64 variants
    std::string Crypto_EncryptSecureBase64(const std::string& plaintext);
    
    // Decrypts the Base64 string. 
    // Returns the plaintext on success, or an empty string "" if tampering/errors occur.
    std::string Crypto_DecryptSecureBase64(const std::string& sealedDataB64);

} // namespace GhostCrypto

#endif // GHOST_CRYPTO_H