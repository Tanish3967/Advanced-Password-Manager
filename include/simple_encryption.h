#pragma once

#include <string>
#include <vector>

class SimpleEncryption {
private:
    static const int KEY_SIZE = 32;
    static const int IV_SIZE = 16;
    static const int SALT_SIZE = 32;

public:
    // Simple XOR-based encryption (for demonstration only - NOT secure for production)
    static std::string encrypt_string(const std::string& plaintext, const std::string& password);
    static std::string decrypt_string(const std::string& encrypted_text, const std::string& password);

    // Generate random bytes
    static std::vector<unsigned char> generate_random_bytes(size_t length);

    // Simple hash function (for demonstration only)
    static std::string hash_password(const std::string& password);
};
