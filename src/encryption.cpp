#include "../include/encryption.h"
#include "../include/utils.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pkcs5.h>
#include <iostream>
#include <stdexcept>

std::vector<unsigned char> Encryption::generate_salt() {
    std::vector<unsigned char> salt(SALT_SIZE);
    if (RAND_bytes(salt.data(), SALT_SIZE) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }
    return salt;
}

std::vector<unsigned char> Encryption::derive_key(const std::string& password,
                                                 const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(),
                          10000, // iterations
                          EVP_sha256(),
                          KEY_SIZE, key.data()) != 1) {
        throw std::runtime_error("Failed to derive key");
    }

    return key;
}

std::vector<unsigned char> Encryption::encrypt(const std::vector<unsigned char>& data,
                                              const std::vector<unsigned char>& key,
                                              const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }

    std::vector<unsigned char> encrypted(data.size() + EVP_MAX_BLOCK_LENGTH);
    int len;

    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }

    EVP_CIPHER_CTX_free(ctx);
    encrypted.resize(len + final_len);
    return encrypted;
}

std::vector<unsigned char> Encryption::decrypt(const std::vector<unsigned char>& encrypted_data,
                                              const std::vector<unsigned char>& key,
                                              const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize decryption");
    }

    std::vector<unsigned char> decrypted(encrypted_data.size());
    int len;

    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted_data.data(), encrypted_data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize decryption");
    }

    EVP_CIPHER_CTX_free(ctx);
    decrypted.resize(len + final_len);
    return decrypted;
}

std::string Encryption::encrypt_string(const std::string& plaintext, const std::string& password) {
    auto salt = generate_salt();
    auto key = derive_key(password, salt);
    auto iv = generate_random_bytes(IV_SIZE);

    std::vector<unsigned char> data(plaintext.begin(), plaintext.end());
    auto encrypted = encrypt(data, key, iv);

    // Combine salt + iv + encrypted data
    std::vector<unsigned char> combined;
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), encrypted.begin(), encrypted.end());

    return Utils::base64_encode(combined);
}

std::string Encryption::decrypt_string(const std::string& encrypted_text, const std::string& password) {
    auto combined = Utils::base64_decode(encrypted_text);

    if (combined.size() < SALT_SIZE + IV_SIZE) {
        throw std::runtime_error("Invalid encrypted data");
    }

    // Extract salt, iv, and encrypted data
    std::vector<unsigned char> salt(combined.begin(), combined.begin() + SALT_SIZE);
    std::vector<unsigned char> iv(combined.begin() + SALT_SIZE, combined.begin() + SALT_SIZE + IV_SIZE);
    std::vector<unsigned char> encrypted_data(combined.begin() + SALT_SIZE + IV_SIZE, combined.end());

    auto key = derive_key(password, salt);
    auto decrypted = decrypt(encrypted_data, key, iv);

    return std::string(decrypted.begin(), decrypted.end());
}

std::vector<unsigned char> Encryption::generate_random_bytes(size_t length) {
    std::vector<unsigned char> bytes(length);
    if (RAND_bytes(bytes.data(), length) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return bytes;
}
