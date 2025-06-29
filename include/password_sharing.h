#ifndef PASSWORD_SHARING_H
#define PASSWORD_SHARING_H

#include <string>
#include <vector>
#include "password_manager.h"

// Data structure for password sharing
struct ShareData {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string category;
    std::string expiry_date;
    std::string share_id;
    std::string created_timestamp;
    std::string expires_at;
    std::string share_method;  // "text", "file", "link", "email"
};

class PasswordSharing {
public:
    // Main sharing methods
    static std::string share_password_text(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours);

    static std::string share_password_file(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours);

    static std::string share_password_link(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours);

    static std::string share_password_email(const PasswordEntry& entry,
                                           const std::string& share_password,
                                           int expiry_hours);

    // Import methods
    static ShareData import_from_text(const std::string& text_data,
                                     const std::string& share_password);

    static ShareData import_from_file(const std::string& filename,
                                     const std::string& share_password);

    static ShareData import_from_link(const std::string& link_data,
                                     const std::string& share_password);

    // Utility methods
    static std::string generate_share_id();
    static std::string generate_shareable_text(const ShareData& data);
    static bool validate_share_data(const ShareData& data);
    static bool is_share_expired(const std::string& expires_at);

    // Encryption methods
    static std::string encrypt_share_data(const std::string& data, const std::string& key);
    static std::string decrypt_share_data(const std::string& encrypted_data, const std::string& key);

    // File operations
    static bool save_share_to_file(const std::string& data, const std::string& filename);
    static std::string read_share_from_file(const std::string& filename);

    // Encoding methods
    static std::string base64_encode(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> base64_decode(const std::string& encoded);
    static std::string url_encode(const std::string& data);
    static std::string url_decode(const std::string& str);

    // Simple encryption
    static std::string simple_xor_encrypt(const std::string& data, const std::string& key);
    static std::string simple_xor_decrypt(const std::string& encrypted_data, const std::string& key);
};

#endif // PASSWORD_SHARING_H
