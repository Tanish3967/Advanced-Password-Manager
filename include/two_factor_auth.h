#ifndef TWO_FACTOR_AUTH_H
#define TWO_FACTOR_AUTH_H

#include <string>
#include <vector>
#include <ctime>

class TwoFactorAuth {
public:
    // TOTP (Time-based One-Time Password) generation
    static std::string generate_totp(const std::string& secret, int digits = 6, int period = 30);
    static std::string generate_totp_uri(const std::string& secret, const std::string& account,
                                        const std::string& issuer = "PasswordManager");

    // QR Code generation for authenticator apps
    static std::string generate_qr_code_data(const std::string& secret, const std::string& account,
                                            const std::string& issuer = "PasswordManager");

    // Secret generation and validation
    static std::string generate_secret(size_t length = 32);
    static bool validate_secret(const std::string& secret);

    // Backup codes generation
    static std::vector<std::string> generate_backup_codes(int count = 10, int length = 8);
    static bool validate_backup_code(const std::string& code, const std::vector<std::string>& backup_codes);

    // Utility functions
    static std::string base32_encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base32_decode(const std::string& encoded);
    static std::vector<unsigned char> hmac_sha1(const std::vector<unsigned char>& key, const std::vector<unsigned char>& data);

    // Time utilities
    static uint64_t get_current_timestamp();
    static std::string format_time_remaining(int period = 30);

private:
    static const std::string BASE32_CHARS;
    static const int DEFAULT_PERIOD = 30;
    static const int DEFAULT_DIGITS = 6;
};

#endif // TWO_FACTOR_AUTH_H
