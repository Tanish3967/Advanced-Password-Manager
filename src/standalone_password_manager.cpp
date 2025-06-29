#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <ctime>
#include <limits>

// Password entry structure
struct PasswordEntry {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string category;
    std::string tags;
    time_t created_date;
};

// Simple encryption for portability
class SimpleEncryption {
public:
    static std::string encrypt(const std::string& data, const std::string& key) {
        std::string result;
        for (size_t i = 0; i < data.length(); ++i) {
            result += data[i] ^ key[i % key.length()];
        }
        return base64_encode(result);
    }

    static std::string decrypt(const std::string& encrypted_data, const std::string& key) {
        std::string decoded = base64_decode(encrypted_data);
        std::string result;
        for (size_t i = 0; i < decoded.length(); ++i) {
            result += decoded[i] ^ key[i % key.length()];
        }
        return result;
    }

private:
    static std::string base64_encode(const std::string& data) {
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

    static std::string base64_decode(const std::string& encoded) {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string result;
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
};

// Password sharing functionality
class PasswordSharing {
public:
    struct ShareData {
        std::string service;
        std::string username;
        std::string password;
        std::string notes;
        std::string category;
        std::string share_id;
        std::string created_timestamp;
        std::string expires_at;
        std::string share_method;
    };

    static std::string share_password_text(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours) {
        ShareData data;
        data.service = entry.service;
        data.username = entry.username;
        data.password = entry.password;
        data.notes = entry.notes;
        data.category = entry.category;
        data.share_id = generate_share_id();
        data.created_timestamp = std::to_string(std::time(nullptr));
        data.share_method = "text";

        // Calculate expiry time
        time_t now = time(nullptr);
        time_t expiry_time = now + (expiry_hours * 3600);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&expiry_time), "%Y-%m-%d %H:%M:%S");
        data.expires_at = ss.str();

        // Generate shareable text
        std::string shareable_text = generate_shareable_text(data);

        // Encrypt if share password is provided
        if (!share_password.empty()) {
            shareable_text = SimpleEncryption::encrypt(shareable_text, share_password);
        }

        // Create formatted output
        std::stringstream result;
        result << "=== PASSWORD SHARING (TEXT) ===\n";
        result << "✅ Share ID: " << data.share_id << "\n";
        result << "⏰ Expires: " << data.expires_at << "\n";
        result << "🔐 Protected: " << (share_password.empty() ? "No" : "Yes") << "\n\n";
        result << "📋 Copy this text to share:\n";
        result << "─────────────────────────────────────────\n";
        result << shareable_text << "\n";
        result << "─────────────────────────────────────────\n\n";
        result << "📝 Instructions:\n";
        result << "1. Copy the text above\n";
        result << "2. Send via secure messaging (Signal, WhatsApp, etc.)\n";
        result << "3. Recipient can import using 'Import from Text' option\n";
        if (!share_password.empty()) {
            result << "4. Share the password '" << share_password << "' separately\n";
        }

        return result.str();
    }

    static std::string share_password_file(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours) {
        ShareData data;
        data.service = entry.service;
        data.username = entry.username;
        data.password = entry.password;
        data.notes = entry.notes;
        data.category = entry.category;
        data.share_id = generate_share_id();
        data.created_timestamp = std::to_string(std::time(nullptr));
        data.share_method = "file";

        // Calculate expiry time
        time_t now = time(nullptr);
        time_t expiry_time = now + (expiry_hours * 3600);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&expiry_time), "%Y-%m-%d %H:%M:%S");
        data.expires_at = ss.str();

        // Generate shareable text
        std::string shareable_text = generate_shareable_text(data);

        // Encrypt if share password is provided
        if (!share_password.empty()) {
            shareable_text = SimpleEncryption::encrypt(shareable_text, share_password);
        }

        // Create filename
        std::string filename = "password_share_" + data.share_id + ".txt";

        // Save to file
        std::ofstream file(filename);
        if (file.is_open()) {
            file << shareable_text;
            file.close();

            std::stringstream result;
            result << "=== PASSWORD SHARING (FILE) ===\n";
            result << "✅ File saved: " << filename << "\n";
            result << "⏰ Expires: " << data.expires_at << "\n";
            result << "🔐 Protected: " << (share_password.empty() ? "No" : "Yes") << "\n\n";
            result << "📁 File Contents:\n";
            result << "─────────────────────────────────────────\n";
            result << shareable_text << "\n";
            result << "─────────────────────────────────────────\n\n";
            result << "📝 Instructions:\n";
            result << "1. Send the file '" << filename << "' to recipient\n";
            result << "2. Recipient can import using 'Import from File' option\n";
            if (!share_password.empty()) {
                result << "3. Share the password '" << share_password << "' separately\n";
            }
            result << "4. Delete the file after sharing for security\n";
            return result.str();
        } else {
            return "❌ Error: Could not save file\n";
        }
    }

    static std::string share_password_link(const PasswordEntry& entry,
                                          const std::string& share_password,
                                          int expiry_hours) {
        ShareData data;
        data.service = entry.service;
        data.username = entry.username;
        data.password = entry.password;
        data.notes = entry.notes;
        data.category = entry.category;
        data.share_id = generate_share_id();
        data.created_timestamp = std::to_string(std::time(nullptr));
        data.share_method = "link";

        // Calculate expiry time
        time_t now = time(nullptr);
        time_t expiry_time = now + (expiry_hours * 3600);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&expiry_time), "%Y-%m-%d %H:%M:%S");
        data.expires_at = ss.str();

        // Generate shareable text
        std::string shareable_text = generate_shareable_text(data);

        // Encrypt if share password is provided
        if (!share_password.empty()) {
            shareable_text = SimpleEncryption::encrypt(shareable_text, share_password);
        }

        // Create secure link (using a simple URL encoding approach)
        std::string encoded_data = url_encode(shareable_text);
        std::string secure_link = "https://password-share.example.com/share/" + data.share_id + "?data=" + encoded_data;

        std::stringstream result;
        result << "=== PASSWORD SHARING (LINK) ===\n";
        result << "✅ Share ID: " << data.share_id << "\n";
        result << "⏰ Expires: " << data.expires_at << "\n";
        result << "🔐 Protected: " << (share_password.empty() ? "No" : "Yes") << "\n\n";
        result << "🔗 Secure Link:\n";
        result << "─────────────────────────────────────────\n";
        result << secure_link << "\n";
        result << "─────────────────────────────────────────\n\n";
        result << "📝 Instructions:\n";
        result << "1. Send the link above to recipient\n";
        result << "2. Recipient can visit the link to get the data\n";
        result << "3. Use 'Import from Link' option to import\n";
        if (!share_password.empty()) {
            result << "4. Share the password '" << share_password << "' separately\n";
        }
        result << "⚠️  Note: This is a demo link format\n";

        return result.str();
    }

    static ShareData import_from_text(const std::string& text_data,
                                     const std::string& share_password) {
        ShareData data;
        std::string raw_data = text_data;

        // Try to decrypt if password provided
        if (!share_password.empty()) {
            try {
                raw_data = SimpleEncryption::decrypt(text_data, share_password);
            } catch (...) {
                data.service = "ERROR";
                return data;
            }
        }

        // Parse the data
        std::istringstream iss(raw_data);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.find("Service:") == 0) {
                data.service = line.substr(8);
            } else if (line.find("Username:") == 0) {
                data.username = line.substr(9);
            } else if (line.find("Password:") == 0) {
                data.password = line.substr(9);
            } else if (line.find("Notes:") == 0) {
                data.notes = line.substr(6);
            } else if (line.find("Category:") == 0) {
                data.category = line.substr(9);
            } else if (line.find("Expires:") == 0) {
                data.expires_at = line.substr(8);
            }
        }

        return data;
    }

    static ShareData import_from_file(const std::string& filename,
                                     const std::string& share_password) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            ShareData data;
            data.service = "ERROR";
            return data;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        file.close();

        return import_from_text(content, share_password);
    }

    static ShareData import_from_link(const std::string& link_data,
                                     const std::string& share_password) {
        // Extract data from link format
        std::string data_part = link_data;
        size_t pos = link_data.find("?data=");
        if (pos != std::string::npos) {
            data_part = link_data.substr(pos + 6);
        }

        std::string decoded_data = url_decode(data_part);
        return import_from_text(decoded_data, share_password);
    }

private:
    static std::string generate_share_id() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);
        static const char* hex_chars = "0123456789abcdef";

        std::string id;
        for (int i = 0; i < 8; ++i) {
            id += hex_chars[dis(gen)];
        }
        return id;
    }

    static std::string generate_shareable_text(const ShareData& data) {
        std::stringstream ss;
        ss << "=== PASSWORD SHARE ===\n";
        ss << "Share ID: " << data.share_id << "\n";
        ss << "Service: " << data.service << "\n";
        ss << "Username: " << data.username << "\n";
        ss << "Password: " << data.password << "\n";
        ss << "Notes: " << data.notes << "\n";
        ss << "Category: " << data.category << "\n";
        ss << "Expires: " << data.expires_at << "\n";
        ss << "Created: " << data.created_timestamp << "\n";
        ss << "Method: " << data.share_method << "\n";
        ss << "=====================\n";
        return ss.str();
    }

    static std::string url_encode(const std::string& data) {
        std::string encoded;
        for (char c : data) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            } else {
                char hex[4];
                sprintf(hex, "%%%02X", (unsigned char)c);
                encoded += hex;
            }
        }
        return encoded;
    }

    static std::string url_decode(const std::string& str) {
        std::string decoded;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '%' && i + 2 < str.length()) {
                int value;
                std::istringstream iss(str.substr(i + 1, 2));
                iss >> std::hex >> value;
                decoded += (char)value;
                i += 2;
            } else if (str[i] == '+') {
                decoded += ' ';
            } else {
                decoded += str[i];
            }
        }
        return decoded;
    }
};

// TOTP (Time-based One-Time Password) functionality
class TOTP {
public:
    static std::string generate_totp(const std::string& secret, int digits = 6) {
        time_t now = time(nullptr);
        uint64_t time_step = now / 30; // 30-second intervals

        // Convert time to bytes
        std::vector<uint8_t> time_bytes(8);
        for (int i = 7; i >= 0; --i) {
            time_bytes[i] = time_step & 0xFF;
            time_step >>= 8;
        }

        // Generate HMAC-SHA1 (simplified)
        std::string hmac = simple_hmac_sha1(secret, time_bytes);

        // Generate TOTP
        int offset = hmac[hmac.length() - 1] & 0x0F;
        uint32_t code = ((hmac[offset] & 0x7F) << 24) |
                       ((hmac[offset + 1] & 0xFF) << 16) |
                       ((hmac[offset + 2] & 0xFF) << 8) |
                       (hmac[offset + 3] & 0xFF);

        code = code % static_cast<uint32_t>(pow(10, digits));

        // Format with leading zeros
        std::stringstream ss;
        ss << std::setw(digits) << std::setfill('0') << code;
        return ss.str();
    }

    static std::string generate_secret() {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, chars.length() - 1);

        std::string secret;
        for (int i = 0; i < 32; ++i) {
            secret += chars[dis(gen)];
        }
        return secret;
    }

private:
    static std::string simple_hmac_sha1(const std::string& key, const std::vector<uint8_t>& data) {
        // Simplified HMAC-SHA1 implementation
        std::string combined = key;
        for (uint8_t byte : data) {
            combined += static_cast<char>(byte);
        }
        return simple_hash(combined);
    }

    static std::string simple_hash(const std::string& input) {
        std::hash<std::string> hasher;
        return std::to_string(hasher(input));
    }
};

// Enhanced Password Sharing with time limits
class EnhancedPasswordSharing {
public:
    struct ShareRequest {
        std::string share_id;
        std::string service;
        std::string username;
        std::string password;
        std::string notes;
        std::string category;
        time_t created_time;
        time_t expiry_time;
        std::string access_code;
        bool is_encrypted;
        std::string recipient_email;
    };

    static ShareRequest create_share_request(const PasswordEntry& entry,
                                           int expiry_hours = 24,
                                           const std::string& recipient = "",
                                           bool encrypt = true) {
        ShareRequest request;
        request.share_id = generate_share_id();
        request.service = entry.service;
        request.username = entry.username;
        request.password = entry.password;
        request.notes = entry.notes;
        request.category = entry.category;
        request.created_time = time(nullptr);
        request.expiry_time = request.created_time + (expiry_hours * 3600);
        request.access_code = generate_access_code();
        request.is_encrypted = encrypt;
        request.recipient_email = recipient;
        return request;
    }

    static std::string share_with_time_limit(const ShareRequest& request) {
        std::stringstream result;
        result << "=== ENHANCED PASSWORD SHARING ===\n";
        result << "✅ Share ID: " << request.share_id << "\n";
        result << "⏰ Created: " << format_time(request.created_time) << "\n";
        result << "⏰ Expires: " << format_time(request.expiry_time) << "\n";
        result << "🔐 Access Code: " << request.access_code << "\n";
        result << "🔒 Encrypted: " << (request.is_encrypted ? "Yes" : "No") << "\n";
        if (!request.recipient_email.empty()) {
            result << "📧 Recipient: " << request.recipient_email << "\n";
        }

        // Create shareable data
        std::string share_data = create_share_data(request);
        if (request.is_encrypted) {
            share_data = SimpleEncryption::encrypt(share_data, request.access_code);
        }

        result << "\n📋 Share Data:\n";
        result << "─────────────────────────────────────────\n";
        result << share_data << "\n";
        result << "─────────────────────────────────────────\n";

        return result.str();
    }

    static bool is_share_expired(const ShareRequest& request) {
        return time(nullptr) > request.expiry_time;
    }

private:
    static std::string generate_share_id() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);
        static const char* hex_chars = "0123456789abcdef";

        std::string id;
        for (int i = 0; i < 12; ++i) {
            id += hex_chars[dis(gen)];
        }
        return id;
    }

    static std::string generate_access_code() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 9);

        std::string code;
        for (int i = 0; i < 6; ++i) {
            code += std::to_string(dis(gen));
        }
        return code;
    }

    static std::string create_share_data(const ShareRequest& request) {
        std::stringstream ss;
        ss << "=== ENHANCED PASSWORD SHARE ===\n";
        ss << "Share ID: " << request.share_id << "\n";
        ss << "Service: " << request.service << "\n";
        ss << "Username: " << request.username << "\n";
        ss << "Password: " << request.password << "\n";
        ss << "Notes: " << request.notes << "\n";
        ss << "Category: " << request.category << "\n";
        ss << "Created: " << request.created_time << "\n";
        ss << "Expires: " << request.expiry_time << "\n";
        ss << "Access Code: " << request.access_code << "\n";
        ss << "=====================\n";
        return ss.str();
    }

    static std::string format_time(time_t timestamp) {
        char buffer[26];
        struct tm* timeinfo = localtime(&timestamp);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buffer);
    }
};

// Emergency Access functionality
class EmergencyAccess {
public:
    struct EmergencyContact {
        std::string name;
        std::string email;
        std::string phone;
        time_t access_granted;
        time_t access_expires;
        std::string access_code;
        bool is_active;
    };

    static EmergencyContact create_emergency_contact(const std::string& name,
                                                   const std::string& email,
                                                   const std::string& phone,
                                                   int access_duration_hours = 24) {
        EmergencyContact contact;
        contact.name = name;
        contact.email = email;
        contact.phone = phone;
        contact.access_granted = time(nullptr);
        contact.access_expires = contact.access_granted + (access_duration_hours * 3600);
        contact.access_code = generate_emergency_code();
        contact.is_active = true;
        return contact;
    }

    static std::string grant_emergency_access(const EmergencyContact& contact) {
        std::stringstream result;
        result << "=== EMERGENCY ACCESS GRANTED ===\n";
        result << "👤 Contact: " << contact.name << "\n";
        result << "📧 Email: " << contact.email << "\n";
        result << "📱 Phone: " << contact.phone << "\n";
        result << "⏰ Granted: " << format_time(contact.access_granted) << "\n";
        result << "⏰ Expires: " << format_time(contact.access_expires) << "\n";
        result << "🔑 Access Code: " << contact.access_code << "\n";
        result << "⚠️  Share this code securely with the contact!\n";
        return result.str();
    }

    static bool validate_emergency_access(const EmergencyContact& contact, const std::string& code) {
        if (!contact.is_active) return false;
        if (time(nullptr) > contact.access_expires) return false;
        return contact.access_code == code;
    }

private:
    static std::string generate_emergency_code() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 9);

        std::string code;
        for (int i = 0; i < 8; ++i) {
            code += std::to_string(dis(gen));
        }
        return code;
    }

    static std::string format_time(time_t timestamp) {
        char buffer[26];
        struct tm* timeinfo = localtime(&timestamp);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buffer);
    }
};

// Password Manager Class
class PasswordManager {
private:
    std::map<std::string, PasswordEntry> passwords;
    std::string master_password;
    std::string salt;  // Add salt for password hashing
    std::string data_file = "passwords.dat";
    bool logged_in = false;
    int failed_attempts = 0;
    const int max_attempts = 3;

    // Categories and tags
    std::set<std::string> categories;
    std::set<std::string> tags;
    std::map<std::string, std::set<std::string>> password_categories;
    std::map<std::string, std::set<std::string>> password_tags;

    // Password history
    std::map<std::string, std::vector<std::pair<std::string, time_t>>> password_history;

    // Recovery codes
    std::vector<std::string> recovery_codes;
    std::string security_question;
    std::string security_answer_hash;

    // TOTP secrets for 2FA
    std::map<std::string, std::string> totp_secrets;

    // Enhanced sharing requests
    std::vector<EnhancedPasswordSharing::ShareRequest> share_requests;

    // Emergency contacts
    std::vector<EmergencyAccess::EmergencyContact> emergency_contacts;

    // Usage tracking
    std::map<std::string, int> password_usage_count;
    std::map<std::string, time_t> last_used_times;

public:
    bool login(const std::string& password) {
        std::string password_hash = hash_with_salt(password, salt);
        if (password_hash == master_password) {
            logged_in = true;
            failed_attempts = 0;
            return true;
        } else {
            failed_attempts++;
            if (failed_attempts >= max_attempts) {
                std::cout << "🚨 Too many failed attempts! Self-destruct mode activated.\n";
                trigger_self_destruct();
            }
            return false;
        }
    }

    bool login_with_recovery_code(const std::string& code) {
        if (validate_recovery_code(code)) {
            logged_in = true;
            failed_attempts = 0;
            std::cout << "\n✅ Recovery code accepted. Please set a new master password.\n";
            std::cout << "New master password: ";
            std::string new_password;
            std::getline(std::cin, new_password);
            master_password = hash_with_salt(new_password, salt);
            save_data();
            return true;
        }
        return false;
    }

    void logout() {
        logged_in = false;
    }

    bool is_logged_in() const {
        return logged_in;
    }

    void add_password(const std::string& service, const std::string& username,
                     const std::string& password, const std::string& notes = "",
                     const std::string& category = "", const std::string& tags = "") {
        if (!logged_in) return;

        std::string key = service + ":" + username;

        // Add to history if password already exists
        if (passwords.find(key) != passwords.end()) {
            add_to_history(key, passwords[key].password);
        }

        PasswordEntry entry;
        entry.service = service;
        entry.username = username;
        entry.password = password;
        entry.notes = notes;
        entry.category = category;
        entry.tags = tags;
        entry.created_date = std::time(nullptr);

        passwords[key] = entry;

        // Add to categories and tags
        if (!category.empty()) {
            categories.insert(category);
            password_categories[key].insert(category);
        }

        if (!tags.empty()) {
            std::istringstream iss(tags);
            std::string tag;
            while (std::getline(iss, tag, ',')) {
                tag.erase(0, tag.find_first_not_of(" \t"));
                tag.erase(tag.find_last_not_of(" \t") + 1);
                if (!tag.empty()) {
                    this->tags.insert(tag);
                    password_tags[key].insert(tag);
                }
            }
        }

        save_data();
    }

    bool get_password(const std::string& service, const std::string& username,
                     std::string& password, std::string& notes) {
        if (!logged_in) return false;

        std::string key = service + ":" + username;
        auto it = passwords.find(key);
        if (it != passwords.end()) {
            password = it->second.password;
            notes = it->second.notes;
            return true;
        }
        return false;
    }

    void list_passwords() {
        if (!logged_in) return;

        std::cout << "\n📋 All Passwords:\n";
        std::cout << "================\n";
        for (const auto& pair : passwords) {
            std::cout << "Service: " << pair.second.service << "\n";
            std::cout << "Username: " << pair.second.username << "\n";
            std::cout << "Category: " << pair.second.category << "\n";
            std::cout << "Tags: " << pair.second.tags << "\n";
            std::cout << "Created: " << format_date(pair.second.created_date) << "\n";
            std::cout << "----------------\n";
        }
    }

    void search_by_category(const std::string& category) {
        if (!logged_in) return;

        std::cout << "\n🔍 Passwords in category '" << category << "':\n";
        std::cout << "================================\n";
        for (const auto& pair : passwords) {
            if (pair.second.category == category) {
                std::cout << "Service: " << pair.second.service << "\n";
                std::cout << "Username: " << pair.second.username << "\n";
                std::cout << "----------------\n";
            }
        }
    }

    void search_by_tag(const std::string& tag) {
        if (!logged_in) return;

        std::cout << "\n🏷️  Passwords with tag '" << tag << "':\n";
        std::cout << "==============================\n";
        for (const auto& pair : password_tags) {
            if (pair.second.count(tag)) {
                auto it = passwords.find(pair.first);
                if (it != passwords.end()) {
                    std::cout << "Service: " << it->second.service << "\n";
                    std::cout << "Username: " << it->second.username << "\n";
                    std::cout << "----------------\n";
                }
            }
        }
    }

    void show_password_history(const std::string& service, const std::string& username) {
        if (!logged_in) return;

        std::string key = service + ":" + username;
        auto it = password_history.find(key);
        if (it != password_history.end()) {
            std::cout << "\n📜 Password History for " << service << ":" << username << "\n";
            std::cout << "==========================================\n";
            for (size_t i = 0; i < it->second.size(); ++i) {
                std::cout << "Version " << (i + 1) << ": " << it->second[i].first
                          << " (created: " << format_date(it->second[i].second) << ")\n";
            }
        } else {
            std::cout << "No password history found.\n";
        }
    }

    void generate_recovery_codes(int count = 10) {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, chars.length() - 1);

        recovery_codes.clear();
        std::set<std::string> used_codes;

        while (recovery_codes.size() < static_cast<size_t>(count)) {
            std::string code;
            for (int i = 0; i < 8; ++i) {
                code += chars[dis(gen)];
            }
            if (used_codes.find(code) == used_codes.end()) {
                recovery_codes.push_back(code);
                used_codes.insert(code);
            }
        }

        std::cout << "\n🔑 Recovery Codes Generated:\n";
        std::cout << "============================\n";
        for (size_t i = 0; i < recovery_codes.size(); ++i) {
            std::cout << (i + 1) << ". " << recovery_codes[i] << "\n";
        }
        std::cout << "\n⚠️  Save these codes in a secure location!\n";
    }

    bool validate_recovery_code(const std::string& code) {
        return std::find(recovery_codes.begin(), recovery_codes.end(), code) != recovery_codes.end();
    }

    void set_security_question(const std::string& question, const std::string& answer) {
        security_question = question;
        security_answer_hash = hash_with_salt(answer, salt);
        std::cout << "✅ Security question set successfully.\n";
    }

    std::string get_security_question() const {
        return security_question;
    }

    bool validate_security_answer(const std::string& answer) {
        return hash_with_salt(answer, salt) == security_answer_hash;
    }

    std::string check_password_strength(const std::string& password) {
        int score = 0;
        bool has_upper = false, has_lower = false, has_digit = false, has_special = false;

        for (char c : password) {
            if (isupper(c)) has_upper = true;
            else if (islower(c)) has_lower = true;
            else if (isdigit(c)) has_digit = true;
            else has_special = true;
        }

        score += std::min(20, static_cast<int>(password.length()) * 2);
        if (has_upper) score += 10;
        if (has_lower) score += 10;
        if (has_digit) score += 10;
        if (has_special) score += 15;

        std::string strength;
        if (score >= 80) strength = "🟢 Very Strong";
        else if (score >= 60) strength = "🟡 Strong";
        else if (score >= 40) strength = "🟠 Moderate";
        else if (score >= 20) strength = "🔴 Weak";
        else strength = "🔴 Very Weak";

        return "Score: " + std::to_string(score) + "/100 - " + strength;
    }

    std::string generate_strong_password(int length = 16) {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, chars.length() - 1);

        std::string password;
        for (int i = 0; i < length; ++i) {
            password += chars[dis(gen)];
        }

        return password;
    }

    void export_to_mobile(const std::string& filename) {
        if (!logged_in) return;

        std::ofstream file(filename);
        if (file.is_open()) {
            file << "MOBILE_EXPORT_V1\n";
            file << "TIMESTAMP:" << std::time(nullptr) << "\n";
            file << "PASSWORDS:\n";

            for (const auto& pair : passwords) {
                file << "SERVICE:" << pair.second.service << "\n";
                file << "USERNAME:" << pair.second.username << "\n";
                file << "PASSWORD:" << pair.second.password << "\n";
                file << "NOTES:" << pair.second.notes << "\n";
                file << "CATEGORY:" << pair.second.category << "\n";
                file << "TAGS:" << pair.second.tags << "\n";
                file << "---\n";
            }

            file.close();
            std::cout << "✅ Passwords exported to " << filename << "\n";
        } else {
            std::cout << "❌ Failed to export passwords.\n";
        }
    }

    void import_from_mobile(const std::string& filename) {
        if (!logged_in) return;

        std::ifstream file(filename);
        if (file.is_open()) {
            std::string line;
            std::string current_service, current_username, current_password, current_notes, current_category, current_tags;
            bool in_password_block = false;

            while (std::getline(file, line)) {
                if (line == "---") {
                    if (in_password_block) {
                        add_password(current_service, current_username, current_password,
                                   current_notes, current_category, current_tags);
                        current_service = current_username = current_password = current_notes = current_category = current_tags = "";
                        in_password_block = false;
                    }
                } else if (line.find("SERVICE:") == 0) {
                    current_service = line.substr(8);
                    in_password_block = true;
                } else if (line.find("USERNAME:") == 0) {
                    current_username = line.substr(9);
                } else if (line.find("PASSWORD:") == 0) {
                    current_password = line.substr(9);
                } else if (line.find("NOTES:") == 0) {
                    current_notes = line.substr(6);
                } else if (line.find("CATEGORY:") == 0) {
                    current_category = line.substr(9);
                } else if (line.find("TAGS:") == 0) {
                    current_tags = line.substr(5);
                }
            }

            // Add the last password if exists
            if (in_password_block) {
                add_password(current_service, current_username, current_password,
                           current_notes, current_category, current_tags);
            }

            file.close();
            std::cout << "✅ Passwords imported from " << filename << "\n";
        } else {
            std::cout << "❌ Failed to import passwords.\n";
        }
    }

    // Password sharing methods
    void share_password(const std::string& service, const std::string& username) {
        if (!logged_in) return;

        std::string key = service + ":" + username;
        auto it = passwords.find(key);
        if (it == passwords.end()) {
            std::cout << "❌ Password not found.\n";
            return;
        }

        std::cout << "\n🔗 Password Sharing Options:\n";
        std::cout << "============================\n";
        std::cout << "1. Share via Text\n";
        std::cout << "2. Share via File\n";
        std::cout << "3. Share via Link\n";
        std::cout << "4. Back to main menu\n";
        std::cout << "Choose option: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice >= 1 && choice <= 3) {
            std::string share_password;
            std::cout << "Enter share password (or press Enter for no encryption): ";
            std::getline(std::cin, share_password);

            int expiry_hours;
            std::cout << "Enter expiry time in hours (24): ";
            std::string expiry_input;
            std::getline(std::cin, expiry_input);
            expiry_hours = expiry_input.empty() ? 24 : std::stoi(expiry_input);

            std::string result;
            switch (choice) {
                case 1:
                    result = PasswordSharing::share_password_text(it->second, share_password, expiry_hours);
                    break;
                case 2:
                    result = PasswordSharing::share_password_file(it->second, share_password, expiry_hours);
                    break;
                case 3:
                    result = PasswordSharing::share_password_link(it->second, share_password, expiry_hours);
                    break;
            }
            std::cout << result << "\n";
        }
    }

    void import_shared_password() {
        if (!logged_in) return;

        std::cout << "\n📥 Import Shared Password:\n";
        std::cout << "==========================\n";
        std::cout << "1. Import from Text\n";
        std::cout << "2. Import from File\n";
        std::cout << "3. Import from Link\n";
        std::cout << "4. Back to main menu\n";
        std::cout << "Choose option: ";

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice >= 1 && choice <= 3) {
            std::string input_data;
            std::string share_password;

            switch (choice) {
                case 1:
                    std::cout << "Paste the shared text data:\n";
                    std::getline(std::cin, input_data);
                    break;
                case 2:
                    std::cout << "Enter filename: ";
                    std::getline(std::cin, input_data);
                    break;
                case 3:
                    std::cout << "Paste the shared link:\n";
                    std::getline(std::cin, input_data);
                    break;
            }

            std::cout << "Enter share password (if encrypted): ";
            std::getline(std::cin, share_password);

            PasswordSharing::ShareData imported_data;
            switch (choice) {
                case 1:
                    imported_data = PasswordSharing::import_from_text(input_data, share_password);
                    break;
                case 2:
                    imported_data = PasswordSharing::import_from_file(input_data, share_password);
                    break;
                case 3:
                    imported_data = PasswordSharing::import_from_link(input_data, share_password);
                    break;
            }

            if (imported_data.service != "ERROR") {
                std::cout << "\n✅ Password imported successfully:\n";
                std::cout << "Service: " << imported_data.service << "\n";
                std::cout << "Username: " << imported_data.username << "\n";
                std::cout << "Category: " << imported_data.category << "\n";
                std::cout << "Notes: " << imported_data.notes << "\n";

                std::cout << "\nAdd this password to your vault? (y/n): ";
                char confirm;
                std::cin >> confirm;
                if (confirm == 'y' || confirm == 'Y') {
                    add_password(imported_data.service, imported_data.username,
                               imported_data.password, imported_data.notes, imported_data.category);
                    std::cout << "✅ Password added to vault!\n";
                }
            } else {
                std::cout << "❌ Failed to import password. Check the data and password.\n";
            }
        }
    }

    void setup_initial_config() {
        std::cout << "\n🎉 Welcome to Advanced Password Manager!\n";
        std::cout << "========================================\n";

        // Generate a random salt
        salt = generate_salt();

        // Set master password
        std::cout << "Please set your master password: ";
        std::string plain_password;
        std::getline(std::cin, plain_password);
        master_password = hash_with_salt(plain_password, salt);

        // Generate recovery codes
        std::cout << "\nGenerating recovery codes...\n";
        generate_recovery_codes(5);

        // Set security question
        std::cout << "\nSet up a security question for password recovery.\n";
        std::cout << "Question: What was your first pet's name? ";
        std::string answer;
        std::getline(std::cin, answer);
        set_security_question("What was your first pet's name?", answer);

        std::cout << "\n✅ Initial setup completed!\n";
        save_data();
    }

    void load_data() {
        std::ifstream file(data_file);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                if (line.find("SALT:") == 0) {
                    salt = line.substr(5);
                } else if (line.find("MASTER:") == 0) {
                    master_password = line.substr(7);
                } else if (line.find("RECOVERY:") == 0) {
                    recovery_codes.push_back(line.substr(9));
                } else if (line.find("PASSWORD:") == 0) {
                    std::string current_service = SimpleEncryption::decrypt(line.substr(9), master_password);
                    std::string current_username, current_password, current_notes, current_category, current_tags;
                    time_t current_created = 0;
                    bool in_password_block = false;

                    while (std::getline(file, line)) {
                        if (line == "---") {
                            if (in_password_block) {
                                add_password(current_service, current_username, current_password,
                                           current_notes, current_category, current_tags);
                                current_service = current_username = current_password = current_notes = current_category = current_tags = "";
                                in_password_block = false;
                            }
                        } else if (line.find("PASSWORD:") == 0) {
                            current_service = SimpleEncryption::decrypt(line.substr(9), master_password);
                            in_password_block = true;
                        } else if (line.find("USERNAME:") == 0) {
                            current_username = SimpleEncryption::decrypt(line.substr(9), master_password);
                        } else if (line.find("PASS:") == 0) {
                            current_password = SimpleEncryption::decrypt(line.substr(5), master_password);
                        } else if (line.find("NOTES:") == 0) {
                            current_notes = SimpleEncryption::decrypt(line.substr(6), master_password);
                        } else if (line.find("CATEGORY:") == 0) {
                            current_category = SimpleEncryption::decrypt(line.substr(9), master_password);
                        } else if (line.find("TAGS:") == 0) {
                            current_tags = SimpleEncryption::decrypt(line.substr(5), master_password);
                        } else if (line.find("CREATED:") == 0) {
                            current_created = std::stol(line.substr(8));
                        }
                    }
                    file.close();
                }
            }
        }
    }

    // TOTP Methods
    void add_totp_secret(const std::string& service, const std::string& username) {
        if (!logged_in) return;

        std::string key = service + ":" + username;
        std::string secret = TOTP::generate_secret();
        totp_secrets[key] = secret;

        std::cout << "\n🔐 TOTP Secret for " << service << ":" << username << "\n";
        std::cout << "Secret: " << secret << "\n";
        std::cout << "QR Code URL: otpauth://totp/" << service << ":" << username
                  << "?secret=" << secret << "&issuer=PasswordManager\n";
        std::cout << "Add this to your authenticator app (Google Authenticator, Authy, etc.)\n";

        save_data();
    }

    void generate_totp_code(const std::string& service, const std::string& username) {
        if (!logged_in) return;

        std::string key = service + ":" + username;
        auto it = totp_secrets.find(key);
        if (it != totp_secrets.end()) {
            std::string code = TOTP::generate_totp(it->second);
            std::cout << "\n🔐 TOTP Code for " << service << ":" << username << "\n";
            std::cout << "Code: " << code << "\n";
            std::cout << "Valid for 30 seconds\n";
        } else {
            std::cout << "❌ No TOTP secret found for " << service << ":" << username << "\n";
        }
    }

    // Enhanced Password Sharing
    void create_enhanced_share(const std::string& service, const std::string& username) {
        if (!logged_in) return;

        std::string key = service + ":" + username;
        auto it = passwords.find(key);
        if (it == passwords.end()) {
            std::cout << "❌ Password not found.\n";
            return;
        }

        std::cout << "\n🔗 Enhanced Password Sharing\n";
        std::cout << "============================\n";

        int expiry_hours;
        std::cout << "Expiry time in hours (24): ";
        std::string expiry_input;
        std::getline(std::cin, expiry_input);
        expiry_hours = expiry_input.empty() ? 24 : std::stoi(expiry_input);

        std::string recipient;
        std::cout << "Recipient email (optional): ";
        std::getline(std::cin, recipient);

        bool encrypt;
        std::cout << "Encrypt share data? (y/n): ";
        char encrypt_choice;
        std::cin >> encrypt_choice;
        encrypt = (encrypt_choice == 'y' || encrypt_choice == 'Y');
        std::cin.ignore();

        auto request = EnhancedPasswordSharing::create_share_request(
            it->second, expiry_hours, recipient, encrypt);

        share_requests.push_back(request);
        std::cout << EnhancedPasswordSharing::share_with_time_limit(request) << "\n";

        save_data();
    }

    // Emergency Access
    void add_emergency_contact() {
        if (!logged_in) return;

        std::cout << "\n🚨 Add Emergency Contact\n";
        std::cout << "=======================\n";

        std::string name, email, phone;
        std::cout << "Contact name: ";
        std::getline(std::cin, name);
        std::cout << "Email: ";
        std::getline(std::cin, email);
        std::cout << "Phone: ";
        std::getline(std::cin, phone);

        int duration_hours;
        std::cout << "Access duration in hours (24): ";
        std::string duration_input;
        std::getline(std::cin, duration_input);
        duration_hours = duration_input.empty() ? 24 : std::stoi(duration_input);

        auto contact = EmergencyAccess::create_emergency_contact(name, email, phone, duration_hours);
        emergency_contacts.push_back(contact);

        std::cout << EmergencyAccess::grant_emergency_access(contact) << "\n";

        save_data();
    }

    bool emergency_login(const std::string& contact_name, const std::string& access_code) {
        for (auto& contact : emergency_contacts) {
            if (contact.name == contact_name && EmergencyAccess::validate_emergency_access(contact, access_code)) {
                logged_in = true;
                std::cout << "🚨 Emergency access granted for " << contact.name << "\n";
                std::cout << "⚠️  This access will expire at " << format_date(contact.access_expires) << "\n";
                return true;
            }
        }
        return false;
    }

    // Usage Tracking
    void track_password_usage(const std::string& service, const std::string& username) {
        std::string key = service + ":" + username;
        password_usage_count[key]++;
        last_used_times[key] = time(nullptr);
    }

    void show_usage_analytics() {
        if (!logged_in) return;

        std::cout << "\n📊 Password Usage Analytics\n";
        std::cout << "===========================\n";

        // Most used passwords
        std::vector<std::pair<std::string, int> > usage_sorted;
        for (std::map<std::string, int>::const_iterator it = password_usage_count.begin(); it != password_usage_count.end(); ++it) {
            usage_sorted.push_back(*it);
        }

        std::sort(usage_sorted.begin(), usage_sorted.end(),
                 [](const std::pair<std::string, int>& a, const std::pair<std::string, int>& b) {
                     return a.second > b.second;
                 });

        std::cout << "Most Used Passwords:\n";
        for (size_t i = 0; i < std::min(usage_sorted.size(), size_t(5)); ++i) {
            std::map<std::string, PasswordEntry>::const_iterator it = passwords.find(usage_sorted[i].first);
            if (it != passwords.end()) {
                std::cout << (i + 1) << ". " << it->second.service << ":" << it->second.username
                          << " (used " << usage_sorted[i].second << " times)\n";
            }
        }

        // Recently used passwords
        std::vector<std::pair<std::string, time_t> > recent_sorted;
        for (std::map<std::string, time_t>::const_iterator it = last_used_times.begin(); it != last_used_times.end(); ++it) {
            recent_sorted.push_back(*it);
        }

        std::sort(recent_sorted.begin(), recent_sorted.end(),
                 [](const std::pair<std::string, time_t>& a, const std::pair<std::string, time_t>& b) {
                     return a.second > b.second;
                 });

        std::cout << "\nRecently Used Passwords:\n";
        for (size_t i = 0; i < std::min(recent_sorted.size(), size_t(5)); ++i) {
            std::map<std::string, PasswordEntry>::const_iterator it = passwords.find(recent_sorted[i].first);
            if (it != passwords.end()) {
                std::cout << (i + 1) << ". " << it->second.service << ":" << it->second.username
                          << " (last used: " << format_date(recent_sorted[i].second) << ")\n";
            }
        }
    }

private:
    void add_to_history(const std::string& key, const std::string& password) {
        password_history[key].push_back({password, std::time(nullptr)});
    }

    std::string format_date(time_t timestamp) {
        char buffer[26];
        struct tm* timeinfo = localtime(&timestamp);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        return std::string(buffer);
    }

    std::string simple_hash(const std::string& input) {
        std::hash<std::string> hasher;
        return std::to_string(hasher(input));
    }

    std::string generate_salt() {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, chars.length() - 1);

        std::string salt;
        for (int i = 0; i < 16; ++i) {  // 16-character salt
            salt += chars[dis(gen)];
        }
        return salt;
    }

    std::string hash_with_salt(const std::string& password, const std::string& salt) {
        std::string combined = password + salt;
        return simple_hash(combined);
    }

    void trigger_self_destruct() {
        std::cout << "🚨 Self-destruct mode activated!\n";
        std::cout << "Deleting all password data...\n";

        // Delete the data file
        std::remove(data_file.c_str());

        std::cout << "✅ All data has been destroyed.\n";
        std::cout << "Program will now exit.\n";
        exit(0);
    }

    void save_data() {
        std::ofstream file(data_file);
        if (file.is_open()) {
            file << "SALT:" << salt << "\n";
            file << "MASTER:" << master_password << "\n";
            // Save recovery codes
            for (const auto& code : recovery_codes) {
                file << "RECOVERY:" << code << "\n";
            }
            // Save passwords
            for (const auto& pair : passwords) {
                file << "PASSWORD:" << SimpleEncryption::encrypt(pair.second.service, master_password) << "\n";
                file << "USERNAME:" << SimpleEncryption::encrypt(pair.second.username, master_password) << "\n";
                file << "PASS:" << SimpleEncryption::encrypt(pair.second.password, master_password) << "\n";
                file << "NOTES:" << SimpleEncryption::encrypt(pair.second.notes, master_password) << "\n";
                file << "CATEGORY:" << SimpleEncryption::encrypt(pair.second.category, master_password) << "\n";
                file << "TAGS:" << SimpleEncryption::encrypt(pair.second.tags, master_password) << "\n";
                file << "CREATED:" << pair.second.created_date << "\n";
                file << "---\n";
            }
            file.close();
        }
    }
};

// Menu functions
void show_main_menu() {
    std::cout << "\n==============================\n";
    std::cout << "🔐 Password Manager - Main Menu\n";
    std::cout << "==============================\n";
    std::cout << "1. Add Password\n";
    std::cout << "2. Get Password\n";
    std::cout << "3. List All Passwords\n";
    std::cout << "4. Search by Category\n";
    std::cout << "5. Search by Tag\n";
    std::cout << "6. Password History\n";
    std::cout << "7. Password Strength Checker\n";
    std::cout << "8. Generate Strong Password\n";
    std::cout << "9. Recovery Options\n";
    std::cout << "10. Mobile Export/Import\n";
    std::cout << "11. Share Password\n";
    std::cout << "12. Import Shared Password\n";
    std::cout << "13. TOTP (2FA) Management\n";
    std::cout << "14. Enhanced Password Sharing\n";
    std::cout << "15. Emergency Access\n";
    std::cout << "16. Usage Analytics\n";
    std::cout << "17. Help/About\n";
    std::cout << "0. Logout\n";
    std::cout << "==============================\n";
    std::cout << "Enter your choice: ";
}

void add_password(PasswordManager& pm) {
    std::string service, username, password, notes, category, tags;

    std::cout << "\n📝 Add New Password\n";
    std::cout << "==================\n";

    std::cout << "Service/Website: ";
    std::getline(std::cin, service);

    std::cout << "Username/Email: ";
    std::getline(std::cin, username);

    std::cout << "Password: ";
    std::getline(std::cin, password);

    std::cout << "Notes (optional): ";
    std::getline(std::cin, notes);

    std::cout << "Category (optional): ";
    std::getline(std::cin, category);

    std::cout << "Tags (comma-separated, optional): ";
    std::getline(std::cin, tags);

    pm.add_password(service, username, password, notes, category, tags);
    std::cout << "✅ Password added successfully!\n";
}

void get_password(PasswordManager& pm) {
    std::string service, username, password, notes;

    std::cout << "\n🔍 Get Password\n";
    std::cout << "==============\n";

    std::cout << "Service/Website: ";
    std::getline(std::cin, service);

    std::cout << "Username/Email: ";
    std::getline(std::cin, username);

    if (pm.get_password(service, username, password, notes)) {
        std::cout << "\n✅ Password found!\n";
        std::cout << "Password: " << password << "\n";
        if (!notes.empty()) {
            std::cout << "Notes: " << notes << "\n";
        }
    } else {
        std::cout << "❌ Password not found.\n";
    }
}

void search_by_category(PasswordManager& pm) {
    std::string category;
    std::cout << "\n🔍 Search by Category\n";
    std::cout << "====================\n";
    std::cout << "Enter category: ";
    std::getline(std::cin, category);
    pm.search_by_category(category);
}

void search_by_tag(PasswordManager& pm) {
    std::string tag;
    std::cout << "\n🏷️  Search by Tag\n";
    std::cout << "================\n";
    std::cout << "Enter tag: ";
    std::getline(std::cin, tag);
    pm.search_by_tag(tag);
}

void password_history(PasswordManager& pm) {
    std::string service, username;
    std::cout << "\n📜 Password History\n";
    std::cout << "===================\n";
    std::cout << "Service/Website: ";
    std::getline(std::cin, service);
    std::cout << "Username/Email: ";
    std::getline(std::cin, username);
    pm.show_password_history(service, username);
}

void check_password_strength() {
    std::string password;
    std::cout << "\n🔐 Password Strength Checker\n";
    std::cout << "============================\n";
    std::cout << "Enter password to check: ";
    std::getline(std::cin, password);

    PasswordManager pm;
    std::string strength = pm.check_password_strength(password);
    std::cout << "Strength: " << strength << "\n";
}

void generate_strong_password() {
    int length;
    std::cout << "\n🔑 Generate Strong Password\n";
    std::cout << "===========================\n";
    std::cout << "Password length (default 16): ";
    std::string input;
    std::getline(std::cin, input);

    if (input.empty()) {
        length = 16;
    } else {
        length = std::stoi(input);
    }

    PasswordManager pm;
    std::string password = pm.generate_strong_password(length);
    std::cout << "Generated password: " << password << "\n";
}

void recovery_options(PasswordManager& pm) {
    std::cout << "\n🔑 Recovery Options\n";
    std::cout << "===================\n";
    std::cout << "1. Generate new recovery codes\n";
    std::cout << "2. Set security question\n";
    std::cout << "3. View security question\n";
    std::cout << "Enter choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    switch (choice) {
        case 1:
            pm.generate_recovery_codes(5);
            break;
        case 2: {
            std::string question, answer;
            std::cout << "Security question: ";
            std::getline(std::cin, question);
            std::cout << "Answer: ";
            std::getline(std::cin, answer);
            pm.set_security_question(question, answer);
            break;
        }
        case 3:
            std::cout << "Security question: " << pm.get_security_question() << "\n";
            break;
        default:
            std::cout << "Invalid choice.\n";
    }
}

void mobile_export_import(PasswordManager& pm) {
    std::cout << "\n📱 Mobile Export/Import\n";
    std::cout << "======================\n";
    std::cout << "1. Export passwords\n";
    std::cout << "2. Import passwords\n";
    std::cout << "Enter choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    switch (choice) {
        case 1: {
            std::string filename;
            std::cout << "Export filename: ";
            std::getline(std::cin, filename);
            pm.export_to_mobile(filename);
            break;
        }
        case 2: {
            std::string filename;
            std::cout << "Import filename: ";
            std::getline(std::cin, filename);
            pm.import_from_mobile(filename);
            break;
        }
        default:
            std::cout << "Invalid choice.\n";
    }
}

void share_password(PasswordManager& pm) {
    std::string service, username;
    std::cout << "\n🔗 Share Password\n";
    std::cout << "================\n";
    std::cout << "Service/Website: ";
    std::getline(std::cin, service);
    std::cout << "Username/Email: ";
    std::getline(std::cin, username);
    pm.share_password(service, username);
}

void import_shared_password(PasswordManager& pm) {
    pm.import_shared_password();
}

void totp_management(PasswordManager& pm) {
    std::cout << "\n🔐 TOTP (2FA) Management\n";
    std::cout << "========================\n";
    std::cout << "1. Add TOTP Secret\n";
    std::cout << "2. Generate TOTP Code\n";
    std::cout << "3. Back to main menu\n";
    std::cout << "Choose option: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 1) {
        std::string service, username;
        std::cout << "Service/Website: ";
        std::getline(std::cin, service);
        std::cout << "Username/Email: ";
        std::getline(std::cin, username);
        pm.add_totp_secret(service, username);
    } else if (choice == 2) {
        std::string service, username;
        std::cout << "Service/Website: ";
        std::getline(std::cin, service);
        std::cout << "Username/Email: ";
        std::getline(std::cin, username);
        pm.generate_totp_code(service, username);
    }
}

void enhanced_sharing(PasswordManager& pm) {
    std::string service, username;
    std::cout << "\n🔗 Enhanced Password Sharing\n";
    std::cout << "============================\n";
    std::cout << "Service/Website: ";
    std::getline(std::cin, service);
    std::cout << "Username/Email: ";
    std::getline(std::cin, username);
    pm.create_enhanced_share(service, username);
}

void emergency_access_management(PasswordManager& pm) {
    std::cout << "\n🚨 Emergency Access Management\n";
    std::cout << "==============================\n";
    std::cout << "1. Add Emergency Contact\n";
    std::cout << "2. Emergency Login\n";
    std::cout << "3. Back to main menu\n";
    std::cout << "Choose option: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 1) {
        pm.add_emergency_contact();
    } else if (choice == 2) {
        std::string contact_name, access_code;
        std::cout << "Contact Name: ";
        std::getline(std::cin, contact_name);
        std::cout << "Access Code: ";
        std::getline(std::cin, access_code);
        if (pm.emergency_login(contact_name, access_code)) {
            std::cout << "✅ Emergency access successful!\n";
        } else {
            std::cout << "❌ Emergency access failed!\n";
        }
    }
}

void usage_analytics(PasswordManager& pm) {
    pm.show_usage_analytics();
}

void show_help() {
    std::cout << "\n=== Help & About ===\n";
    std::cout << "Advanced Password Manager v2.0\n";
    std::cout << "Features:\n";
    std::cout << "- Secure password storage with encryption\n";
    std::cout << "- Categories and tags for organization\n";
    std::cout << "- Password history and versioning\n";
    std::cout << "- Password strength checking\n";
    std::cout << "- Strong password generation\n";
    std::cout << "- Recovery codes and security questions\n";
    std::cout << "- Mobile export/import\n";
    std::cout << "- Self-destruct mode for security\n";
    std::cout << "\nThis is a portable, self-contained application.\n";
    std::cout << "No external dependencies required!\n";
}

int main() {
    PasswordManager pm;

    // Check if this is first run
    std::ifstream check_file("passwords.dat");
    if (!check_file.good()) {
        pm.setup_initial_config();
    }
    check_file.close();

    pm.load_data();

    // Login
    std::string password;
    std::cout << "\n🔐 Login to Password Manager\n";
    std::cout << "===========================\n";
    std::cout << "Master Password: ";
    std::getline(std::cin, password);

    if (!pm.login(password)) {
        std::cout << "❌ Invalid password.\n";
        std::cout << "Forgot password? Use a recovery code (Y/N): ";
        char use_recovery;
        std::cin >> use_recovery;
        std::cin.ignore();
        if (use_recovery == 'Y' || use_recovery == 'y') {
            std::string code;
            std::cout << "Enter recovery code: ";
            std::getline(std::cin, code);
            if (!pm.login_with_recovery_code(code)) {
                std::cout << "❌ Invalid recovery code. Exiting.\n";
                return 1;
            }
        } else {
            return 1;
        }
    }

    std::cout << "✅ Login successful!\n";

    // Main application loop
    int choice = -1;
    while (choice != 0) {
        show_main_menu();
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                add_password(pm);
                break;
            case 2:
                get_password(pm);
                break;
            case 3:
                pm.list_passwords();
                break;
            case 4:
                search_by_category(pm);
                break;
            case 5:
                search_by_tag(pm);
                break;
            case 6:
                password_history(pm);
                break;
            case 7:
                check_password_strength();
                break;
            case 8:
                generate_strong_password();
                break;
            case 9:
                recovery_options(pm);
                break;
            case 10:
                mobile_export_import(pm);
                break;
            case 11:
                share_password(pm);
                break;
            case 12:
                import_shared_password(pm);
                break;
            case 13:
                totp_management(pm);
                break;
            case 14:
                enhanced_sharing(pm);
                break;
            case 15:
                emergency_access_management(pm);
                break;
            case 16:
                usage_analytics(pm);
                break;
            case 17:
                show_help();
                break;
            case 0:
                pm.logout();
                std::cout << "Logged out successfully.\n";
                break;
            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0;
}
