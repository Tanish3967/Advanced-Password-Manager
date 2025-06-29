#ifndef ADVANCED_ENCRYPTION_H
#define ADVANCED_ENCRYPTION_H

#include <string>
#include <vector>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

class AdvancedEncryption {
public:
    // AES-256 encryption with proper key derivation
    static std::string encrypt_aes256(const std::string& plaintext, const std::string& password);
    static std::string decrypt_aes256(const std::string& ciphertext, const std::string& password);

    // Key derivation using PBKDF2
    static std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt);

    // Secure random generation
    static std::vector<unsigned char> generate_salt(size_t length = 32);
    static std::vector<unsigned char> generate_iv(size_t length = 16);

    // Utility functions
    static std::string bytes_to_hex(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex);
    static std::string base64_encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base64_decode(const std::string& encoded);

    // Error handling
    static std::string get_last_error();
    static void clear_errors();

private:
    static const int KEY_SIZE = 32;  // 256 bits
    static const int IV_SIZE = 16;   // 128 bits
    static const int SALT_SIZE = 32; // 256 bits
    static const int ITERATIONS = 100000; // PBKDF2 iterations
};

#endif // ADVANCED_ENCRYPTION_H
