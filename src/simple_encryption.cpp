#include "../include/simple_encryption.h"
#include "../include/utils.h"
#include <iostream>
#include <random>
#include <algorithm>
#include <sstream>
#include <iomanip>

std::string SimpleEncryption::encrypt_string(const std::string& plaintext, const std::string& password) {
    // Simple XOR encryption (NOT secure for production use)
    std::string encrypted = plaintext;
    for (size_t i = 0; i < encrypted.length(); ++i) {
        encrypted[i] ^= password[i % password.length()];
    }
    return Utils::base64_encode(std::vector<unsigned char>(encrypted.begin(), encrypted.end()));
}

std::string SimpleEncryption::decrypt_string(const std::string& encrypted_text, const std::string& password) {
    // Simple XOR decryption
    auto decoded = Utils::base64_decode(encrypted_text);
    std::string decrypted(decoded.begin(), decoded.end());

    for (size_t i = 0; i < decrypted.length(); ++i) {
        decrypted[i] ^= password[i % password.length()];
    }
    return decrypted;
}

std::vector<unsigned char> SimpleEncryption::generate_random_bytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < length; ++i) {
        bytes[i] = static_cast<unsigned char>(dis(gen));
    }
    return bytes;
}

std::string SimpleEncryption::hash_password(const std::string& password) {
    // Simple hash function (NOT secure for production use)
    unsigned int hash = 5381;
    for (char c : password) {
        hash = ((hash << 5) + hash) + c;
    }

    std::stringstream ss;
    ss << std::hex << hash;
    return ss.str();
}
