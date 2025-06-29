#include "../include/password_sharing.h"
#include "../include/utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <regex>

std::string PasswordSharing::share_password_text(const PasswordEntry& entry,
                                                 const std::string& share_password,
                                                 int expiry_hours) {
    ShareData data;
    data.service = entry.service;
    data.username = entry.username;
    data.password = entry.password;
    data.notes = entry.notes;
    data.category = entry.category;
    data.expiry_date = entry.expiry_date;
    data.share_id = generate_share_id();
    data.created_timestamp = Utils::get_current_timestamp();
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
        shareable_text = encrypt_share_data(shareable_text, share_password);
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

std::string PasswordSharing::share_password_file(const PasswordEntry& entry,
                                                 const std::string& share_password,
                                                 int expiry_hours) {
    ShareData data;
    data.service = entry.service;
    data.username = entry.username;
    data.password = entry.password;
    data.notes = entry.notes;
    data.category = entry.category;
    data.expiry_date = entry.expiry_date;
    data.share_id = generate_share_id();
    data.created_timestamp = Utils::get_current_timestamp();
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
        shareable_text = encrypt_share_data(shareable_text, share_password);
    }

    // Create filename
    std::string filename = "password_share_" + data.share_id + ".txt";

    // Save to file
    bool saved = save_share_to_file(shareable_text, filename);

    std::stringstream result;
    result << "=== PASSWORD SHARING (FILE) ===\n";
    if (saved) {
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
    } else {
        result << "❌ Error: Could not save file\n";
    }

    return result.str();
}

std::string PasswordSharing::share_password_link(const PasswordEntry& entry,
                                                 const std::string& share_password,
                                                 int expiry_hours) {
    ShareData data;
    data.service = entry.service;
    data.username = entry.username;
    data.password = entry.password;
    data.notes = entry.notes;
    data.category = entry.category;
    data.expiry_date = entry.expiry_date;
    data.share_id = generate_share_id();
    data.created_timestamp = Utils::get_current_timestamp();
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
        shareable_text = encrypt_share_data(shareable_text, share_password);
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

std::string PasswordSharing::share_password_email(const PasswordEntry& entry,
                                                  const std::string& share_password,
                                                  int expiry_hours) {
    ShareData data;
    data.service = entry.service;
    data.username = entry.username;
    data.password = entry.password;
    data.notes = entry.notes;
    data.category = entry.category;
    data.expiry_date = entry.expiry_date;
    data.share_id = generate_share_id();
    data.created_timestamp = Utils::get_current_timestamp();
    data.share_method = "email";

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
        shareable_text = encrypt_share_data(shareable_text, share_password);
    }

    // Create email template
    std::string filename = "password_email_" + data.share_id + ".txt";
    std::ofstream email_file(filename);

    std::stringstream result;
    result << "=== PASSWORD SHARING (EMAIL) ===\n";
    result << "✅ Share ID: " << data.share_id << "\n";
    result << "⏰ Expires: " << data.expires_at << "\n";
    result << "🔐 Protected: " << (share_password.empty() ? "No" : "Yes") << "\n\n";

    if (email_file.is_open()) {
        email_file << "Subject: Password Share - " << data.service << " (Expires: " << data.expires_at << ")\n\n";
        email_file << "Hello,\n\n";
        email_file << "I'm sharing a password with you for " << data.service << ".\n\n";
        email_file << "Share Details:\n";
        email_file << "- Service: " << data.service << "\n";
        email_file << "- Username: " << data.username << "\n";
        email_file << "- Category: " << data.category << "\n";
        email_file << "- Expires: " << data.expires_at << "\n";
        email_file << "- Share ID: " << data.share_id << "\n\n";

        if (!share_password.empty()) {
            email_file << "🔐 This password is encrypted. The decryption password is: " << share_password << "\n\n";
        }

        email_file << "Password Data:\n";
        email_file << "─────────────────────────────────────────\n";
        email_file << shareable_text << "\n";
        email_file << "─────────────────────────────────────────\n\n";

        email_file << "Instructions:\n";
        email_file << "1. Copy the password data above\n";
        email_file << "2. Open your password manager\n";
        email_file << "3. Use 'Import from Text' option\n";
        email_file << "4. Paste the data and import\n";
        if (!share_password.empty()) {
            email_file << "5. Enter the decryption password when prompted\n";
        }
        email_file << "\n";
        email_file << "Security Notes:\n";
        email_file << "- This password will expire on " << data.expires_at << "\n";
        email_file << "- Please delete this email after importing\n";
        email_file << "- Never share passwords via unsecured channels\n";
        email_file << "\n";
        email_file << "Best regards,\n";
        email_file << "Password Manager\n";
        email_file.close();

        result << "📧 Email template saved: " << filename << "\n\n";
        result << "📝 Instructions:\n";
        result << "1. Open the email template file\n";
        result << "2. Copy the content to your email client\n";
        result << "3. Send to the recipient\n";
        result << "4. Recipient can import using 'Import from Text' option\n";
        if (!share_password.empty()) {
            result << "5. Share the decryption password separately\n";
        }
    } else {
        result << "❌ Error: Could not create email template\n";
    }

    return result.str();
}

ShareData PasswordSharing::import_from_text(const std::string& text_data,
                                           const std::string& share_password) {
    ShareData data;

    // Check if the data looks like it might be encrypted (Base64-like)
    bool looks_encrypted = false;
    if (text_data.find("PASSWORD_SHARE_V") == std::string::npos) {
        // If it doesn't start with our standard format, it might be encrypted
        looks_encrypted = true;
    }

    // Decrypt if share password is provided or if data looks encrypted
    std::string raw_data = text_data;
    if (!share_password.empty() || looks_encrypted) {
        raw_data = decrypt_share_data(raw_data, share_password);
    }

    // Parse the data
    std::istringstream iss(raw_data);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("SERVICE:") == 0) {
            data.service = line.substr(8);
        } else if (line.find("USERNAME:") == 0) {
            data.username = line.substr(9);
        } else if (line.find("PASSWORD:") == 0) {
            data.password = line.substr(9);
        } else if (line.find("NOTES:") == 0) {
            data.notes = line.substr(6);
        } else if (line.find("CATEGORY:") == 0) {
            data.category = line.substr(9);
        } else if (line.find("EXPIRY:") == 0) {
            data.expiry_date = line.substr(7);
        } else if (line.find("SHARE_ID:") == 0) {
            data.share_id = line.substr(9);
        } else if (line.find("CREATED:") == 0) {
            data.created_timestamp = line.substr(8);
        } else if (line.find("EXPIRES_AT:") == 0) {
            data.expires_at = line.substr(11);
        } else if (line.find("METHOD:") == 0) {
            data.share_method = line.substr(7);
        }
    }

    return data;
}

ShareData PasswordSharing::import_from_file(const std::string& filename,
                                           const std::string& share_password) {
    std::string file_content = read_share_from_file(filename);
    return import_from_text(file_content, share_password);
}

ShareData PasswordSharing::import_from_link(const std::string& link_data,
                                           const std::string& share_password) {
    // Extract data from link (robust extraction)
    std::string data_part = link_data;
    size_t pos = link_data.find("data=");
    if (pos != std::string::npos) {
        data_part = link_data.substr(pos + 5);
        // Only take up to next '&' or end
        size_t end = data_part.find('&');
        if (end != std::string::npos) {
            data_part = data_part.substr(0, end);
        }
        // URL decode
        data_part = url_decode(data_part);
    }
    // If no 'data=' found, treat the whole input as data
    return import_from_text(data_part, share_password);
}

std::string PasswordSharing::generate_share_id() {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);

    std::string share_id;
    for (int i = 0; i < 8; ++i) {
        share_id += chars[dis(gen)];
    }

    return share_id;
}

std::string PasswordSharing::generate_shareable_text(const ShareData& data) {
    std::stringstream ss;
    ss << "PASSWORD_SHARE_V2\n";
    ss << "SERVICE:" << data.service << "\n";
    ss << "USERNAME:" << data.username << "\n";
    ss << "PASSWORD:" << data.password << "\n";
    ss << "NOTES:" << data.notes << "\n";
    ss << "CATEGORY:" << data.category << "\n";
    ss << "EXPIRY:" << data.expiry_date << "\n";
    ss << "SHARE_ID:" << data.share_id << "\n";
    ss << "CREATED:" << data.created_timestamp << "\n";
    ss << "EXPIRES_AT:" << data.expires_at << "\n";
    ss << "METHOD:" << data.share_method << "\n";
    ss << "END_SHARE";

    return ss.str();
}

bool PasswordSharing::validate_share_data(const ShareData& data) {
    // Check if required fields are present
    if (data.service.empty() || data.username.empty() || data.password.empty()) {
        return false;
    }

    // Check if share is expired
    if (!data.expires_at.empty() && is_share_expired(data.expires_at)) {
        return false;
    }

    // Additional validation: check if this looks like valid password data
    // Valid data should have a service name that's not just whitespace
    if (data.service.find_first_not_of(" \t\n\r") == std::string::npos) {
        return false;
    }

    // Username should not be empty or just whitespace
    if (data.username.find_first_not_of(" \t\n\r") == std::string::npos) {
        return false;
    }

    return true;
}

bool PasswordSharing::is_share_expired(const std::string& expires_at) {
    if (expires_at.empty()) return false;

    std::tm tm = {};
    std::istringstream ss(expires_at);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    if (ss.fail()) return false;

    time_t expiry_time = std::mktime(&tm);
    time_t now = time(nullptr);

    return now > expiry_time;
}

std::string PasswordSharing::encrypt_share_data(const std::string& data, const std::string& key) {
    return simple_xor_encrypt(data, key);
}

std::string PasswordSharing::decrypt_share_data(const std::string& encrypted_data, const std::string& key) {
    return simple_xor_decrypt(encrypted_data, key);
}

bool PasswordSharing::save_share_to_file(const std::string& data, const std::string& filename) {
    try {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << data;
            file.close();
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

std::string PasswordSharing::read_share_from_file(const std::string& filename) {
    try {
        std::ifstream file(filename);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            file.close();
            return buffer.str();
        }
        return "";
    } catch (const std::exception& e) {
        return "";
    }
}

std::string PasswordSharing::base64_encode(const std::vector<unsigned char>& data) {
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

std::vector<unsigned char> PasswordSharing::base64_decode(const std::string& encoded) {
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

std::string PasswordSharing::url_encode(const std::string& data) {
    std::string result;
    for (char c : data) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            result += c;
        } else {
            char hex[4];
            sprintf(hex, "%%%02X", (unsigned char)c);
            result += hex;
        }
    }
    return result;
}

std::string PasswordSharing::simple_xor_encrypt(const std::string& data, const std::string& key) {
    if (key.empty()) return data;

    std::string result;
    for (size_t i = 0; i < data.length(); ++i) {
        result += data[i] ^ key[i % key.length()];
    }

    return base64_encode(std::vector<unsigned char>(result.begin(), result.end()));
}

std::string PasswordSharing::simple_xor_decrypt(const std::string& encrypted_data, const std::string& key) {
    if (key.empty()) return encrypted_data;

    std::vector<unsigned char> decoded = base64_decode(encrypted_data);
    std::string result;

    for (size_t i = 0; i < decoded.size(); ++i) {
        result += decoded[i] ^ key[i % key.length()];
    }

    return result;
}

// Add this helper function for URL decoding
std::string PasswordSharing::url_decode(const std::string& str) {
    std::string ret;
    char ch;
    int i, ii;
    for (i = 0; i < str.length(); i++) {
        if (int(str[i]) == 37) {
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        } else {
            ret += str[i];
        }
    }
    return ret;
}
