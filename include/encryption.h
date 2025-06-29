#pragma once

#include <string>
#include <vector>

class Encryption {
private:
    static const int KEY_SIZE = 32; // 256-bit key
    static const int IV_SIZE = 16;  // 128-bit IV
    static const int SALT_SIZE = 32;

public:
    // Generate a random salt
    static std::vector<unsigned char> generate_salt();

    // Derive key from password using PBKDF2
    static std::vector<unsigned char> derive_key(const std::string& password,
                                                const std::vector<unsigned char>& salt);

    // Encrypt data using AES-256-CBC
    static std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv);

    // Decrypt data using AES-256-CBC
    static std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encrypted_data,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv);

    // Encrypt string (convenience function)
    static std::string encrypt_string(const std::string& plaintext, const std::string& password);

    // Decrypt string (convenience function)
    static std::string decrypt_string(const std::string& encrypted_text, const std::string& password);

    // Generate random bytes
    static std::vector<unsigned char> generate_random_bytes(size_t length);
};
