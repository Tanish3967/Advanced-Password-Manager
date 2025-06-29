#include "../include/two_factor_auth.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <ctime>
#include <cstring>
#include <openssl/hmac.h>
#include <openssl/sha.h>

const std::string TwoFactorAuth::BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string TwoFactorAuth::generate_totp(const std::string& secret, int digits, int period) {
    try {
        // Get current timestamp
        uint64_t timestamp = get_current_timestamp();

        // Calculate time step
        uint64_t time_step = timestamp / period;

        // Convert time step to bytes (big-endian)
        std::vector<unsigned char> time_bytes(8);
        for (int i = 7; i >= 0; --i) {
            time_bytes[i] = static_cast<unsigned char>(time_step & 0xFF);
            time_step >>= 8;
        }

        // Decode base32 secret
        auto secret_bytes = base32_decode(secret);

        // Generate HMAC-SHA1
        auto hmac_result = hmac_sha1(secret_bytes, time_bytes);

        // Generate TOTP using RFC 6238 algorithm
        int offset = hmac_result[hmac_result.size() - 1] & 0x0F;

        int code = ((hmac_result[offset] & 0x7F) << 24) |
                   ((hmac_result[offset + 1] & 0xFF) << 16) |
                   ((hmac_result[offset + 2] & 0xFF) << 8) |
                   (hmac_result[offset + 3] & 0xFF);

        code %= static_cast<int>(std::pow(10, digits));

        // Format with leading zeros
        std::stringstream ss;
        ss << std::setw(digits) << std::setfill('0') << code;
        return ss.str();

    } catch (const std::exception& e) {
        throw std::runtime_error("TOTP generation failed: " + std::string(e.what()));
    }
}

std::string TwoFactorAuth::generate_totp_uri(const std::string& secret, const std::string& account, const std::string& issuer) {
    std::stringstream uri;
    uri << "otpauth://totp/";

    // URL encode issuer and account
    if (!issuer.empty()) {
        uri << url_encode(issuer) << ":";
    }
    uri << url_encode(account);

    uri << "?secret=" << secret;
    uri << "&issuer=" << url_encode(issuer);
    uri << "&algorithm=SHA1";
    uri << "&digits=6";
    uri << "&period=30";

    return uri.str();
}

std::string TwoFactorAuth::generate_qr_code_data(const std::string& secret, const std::string& account, const std::string& issuer) {
    return generate_totp_uri(secret, account, issuer);
}

std::string TwoFactorAuth::generate_secret(size_t length) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);

    std::string secret;
    for (size_t i = 0; i < length; ++i) {
        secret += chars[dis(gen)];
    }

    return secret;
}

bool TwoFactorAuth::validate_secret(const std::string& secret) {
    // Check if secret contains only valid base32 characters
    for (char c : secret) {
        if (BASE32_CHARS.find(c) == std::string::npos) {
            return false;
        }
    }

    // Check if length is reasonable (16-32 characters is typical)
    return secret.length() >= 16 && secret.length() <= 32;
}

std::vector<std::string> TwoFactorAuth::generate_backup_codes(int count, int length) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);

    std::vector<std::string> codes;
    std::set<std::string> used_codes; // To ensure uniqueness

    while (codes.size() < static_cast<size_t>(count)) {
        std::string code;
        for (int i = 0; i < length; ++i) {
            code += chars[dis(gen)];
        }

        if (used_codes.find(code) == used_codes.end()) {
            codes.push_back(code);
            used_codes.insert(code);
        }
    }

    return codes;
}

bool TwoFactorAuth::validate_backup_code(const std::string& code, const std::vector<std::string>& backup_codes) {
    return std::find(backup_codes.begin(), backup_codes.end(), code) != backup_codes.end();
}

std::string TwoFactorAuth::base32_encode(const std::vector<unsigned char>& data) {
    std::string result;
    int val = 0, valb = -8;

    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(BASE32_CHARS[(val >> valb) & 0x1F]);
            valb -= 5;
        }
    }

    if (valb > -8) {
        result.push_back(BASE32_CHARS[((val << 8) >> (valb + 8)) & 0x1F]);
    }

    // Add padding
    while (result.size() % 8) {
        result.push_back('=');
    }

    return result;
}

std::vector<unsigned char> TwoFactorAuth::base32_decode(const std::string& encoded) {
    std::vector<unsigned char> result;
    int val = 0, valb = -8;

    for (char c : encoded) {
        if (c == '=') break;

        size_t pos = BASE32_CHARS.find(c);
        if (pos == std::string::npos) continue;

        val = (val << 5) + pos;
        valb += 5;

        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return result;
}

std::vector<unsigned char> TwoFactorAuth::hmac_sha1(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hmac(SHA_DIGEST_LENGTH);
    unsigned int hmac_len;

    HMAC(EVP_sha1(), key.data(), key.size(),
         data.data(), data.size(),
         hmac.data(), &hmac_len);

    hmac.resize(hmac_len);
    return hmac;
}

uint64_t TwoFactorAuth::get_current_timestamp() {
    return static_cast<uint64_t>(std::time(nullptr));
}

std::string TwoFactorAuth::format_time_remaining(int period) {
    uint64_t timestamp = get_current_timestamp();
    int remaining = period - (timestamp % period);

    std::stringstream ss;
    ss << remaining << " seconds";
    return ss.str();
}

// Helper function for URL encoding
std::string TwoFactorAuth::url_encode(const std::string& str) {
    std::string result;
    for (char c : str) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else {
            char hex[4];
            sprintf(hex, "%%%02X", static_cast<unsigned char>(c));
            result += hex;
        }
    }
    return result;
}
