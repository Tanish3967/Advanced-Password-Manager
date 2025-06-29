#pragma once

#include <string>
#include <vector>
#include "password_manager.h"

struct QRCodeData {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string category;
    std::string expiry_date;
    std::string share_id;
    std::string created_timestamp;
    std::string expires_at;
};

class QRCodeGenerator {
public:
    // Generate QR code for password sharing
    static std::string generate_password_qr(const PasswordEntry& entry,
                                           const std::string& share_password = "",
                                           int expiry_hours = 24);

    // Decode QR code data
    static QRCodeData decode_qr_data(const std::string& qr_text,
                                    const std::string& share_password = "");

    // Generate shareable QR text (formatted for easy scanning)
    static std::string generate_shareable_text(const QRCodeData& data);

    // Create actual QR code pattern (scannable)
    static std::string create_qr_pattern(const std::string& data);

    // Create simple ASCII QR representation
    static std::string create_ascii_qr(const std::string& data);

    // Validate QR data
    static bool validate_qr_data(const QRCodeData& data);

    // Generate unique share ID
    static std::string generate_share_id();

    // Check if QR code is expired
    static bool is_qr_expired(const std::string& expires_at);

    // Encrypt/decrypt QR data
    static std::string encrypt_qr_data(const std::string& data, const std::string& key);
    static std::string decrypt_qr_data(const std::string& encrypted_data, const std::string& key);

    // Save QR code to file
    static bool save_qr_to_file(const std::string& qr_data, const std::string& filename);

    // Generate QR code URL for online scanning
    static std::string generate_qr_url(const std::string& data);

private:
    static std::string base64_encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base64_decode(const std::string& encoded);
    static std::string simple_xor_encrypt(const std::string& data, const std::string& key);
    static std::string simple_xor_decrypt(const std::string& encrypted_data, const std::string& key);

    // QR code generation helpers
    static std::string create_simple_qr_matrix(const std::string& data);
    static std::string url_encode(const std::string& data);
};
