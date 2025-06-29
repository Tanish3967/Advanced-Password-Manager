#include "../include/advanced_encryption.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>

// Initialize OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

std::string AdvancedEncryption::encrypt_aes256(const std::string& plaintext, const std::string& password) {
    try {
        // Generate salt and IV
        auto salt = generate_salt(SALT_SIZE);
        auto iv = generate_iv(IV_SIZE);

        // Derive key from password
        auto key = derive_key(password, salt);

        // Initialize encryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create encryption context");
        }

        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        // Prepare output buffer
        std::vector<unsigned char> ciphertext(plaintext.length() + EVP_MAX_BLOCK_LENGTH);
        int len;

        // Encrypt data
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                             reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                             plaintext.length()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }

        int ciphertext_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        // Resize to actual length
        ciphertext.resize(ciphertext_len);

        // Combine salt + IV + ciphertext
        std::vector<unsigned char> result;
        result.insert(result.end(), salt.begin(), salt.end());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());

        // Return base64 encoded result
        return base64_encode(result);

    } catch (const std::exception& e) {
        clear_errors();
        throw std::runtime_error("Encryption failed: " + std::string(e.what()));
    }
}

std::string AdvancedEncryption::decrypt_aes256(const std::string& ciphertext, const std::string& password) {
    try {
        // Decode base64
        auto data = base64_decode(ciphertext);

        if (data.size() < SALT_SIZE + IV_SIZE) {
            throw std::runtime_error("Invalid ciphertext format");
        }

        // Extract salt, IV, and encrypted data
        auto salt = std::vector<unsigned char>(data.begin(), data.begin() + SALT_SIZE);
        auto iv = std::vector<unsigned char>(data.begin() + SALT_SIZE, data.begin() + SALT_SIZE + IV_SIZE);
        auto encrypted_data = std::vector<unsigned char>(data.begin() + SALT_SIZE + IV_SIZE, data.end());

        // Derive key from password
        auto key = derive_key(password, salt);

        // Initialize decryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create decryption context");
        }

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        // Prepare output buffer
        std::vector<unsigned char> plaintext(encrypted_data.size());
        int len;

        // Decrypt data
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data.data(), encrypted_data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }

        int plaintext_len = len;

        // Finalize decryption
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }

        plaintext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        // Resize to actual length
        plaintext.resize(plaintext_len);

        // Convert to string
        return std::string(plaintext.begin(), plaintext.end());

    } catch (const std::exception& e) {
        clear_errors();
        throw std::runtime_error("Decryption failed: " + std::string(e.what()));
    }
}

std::vector<unsigned char> AdvancedEncryption::derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          ITERATIONS,
                          EVP_sha256(),
                          key.size(), key.data()) != 1) {
        throw std::runtime_error("Failed to derive key");
    }

    return key;
}

std::vector<unsigned char> AdvancedEncryption::generate_salt(size_t length) {
    std::vector<unsigned char> salt(length);

    if (RAND_bytes(salt.data(), length) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }

    return salt;
}

std::vector<unsigned char> AdvancedEncryption::generate_iv(size_t length) {
    std::vector<unsigned char> iv(length);

    if (RAND_bytes(iv.data(), length) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    return iv;
}

std::string AdvancedEncryption::bytes_to_hex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (unsigned char byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }

    return ss.str();
}

std::vector<unsigned char> AdvancedEncryption::hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string AdvancedEncryption::base64_encode(const std::vector<unsigned char>& data) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;

    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

std::vector<unsigned char> AdvancedEncryption::base64_decode(const std::string& encoded) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> result;
    int val = 0, valb = -8;

    for (char c : encoded) {
        if (c == '=') break;

        size_t pos = chars.find(c);
        if (pos == std::string::npos) continue;

        val = (val << 6) + pos;
        valb += 6;

        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return result;
}

std::string AdvancedEncryption::get_last_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "No error";

    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    return std::string(err_buf);
}

void AdvancedEncryption::clear_errors() {
    ERR_clear_error();
}
