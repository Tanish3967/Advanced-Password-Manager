#include "../include/qr_code.h"
#include "../include/utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <ctime>
#include <fstream>

std::string QRCodeGenerator::generate_password_qr(const PasswordEntry& entry,
                                                 const std::string& share_password,
                                                 int expiry_hours) {
    QRCodeData data;
    data.service = entry.service;
    data.username = entry.username;
    data.password = entry.password;
    data.notes = entry.notes;
    data.category = entry.category;
    data.expiry_date = entry.expiry_date;
    data.share_id = generate_share_id();
    data.created_timestamp = Utils::get_current_timestamp();

    // Calculate expiry time
    time_t now = time(nullptr);
    time_t expiry_time = now + (expiry_hours * 3600);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&expiry_time), "%Y-%m-%d %H:%M:%S");
    data.expires_at = ss.str();

    // Generate the shareable text
    std::string shareable_text = generate_shareable_text(data);

    // Encrypt if share password is provided
    if (!share_password.empty()) {
        shareable_text = encrypt_qr_data(shareable_text, share_password);
    }

    // Generate QR code representation
    std::string qr_result = create_qr_pattern(shareable_text);

    // Also generate ASCII version for display
    std::string ascii_qr = create_ascii_qr(shareable_text);

    return qr_result + "\n\n" + ascii_qr;
}

QRCodeData QRCodeGenerator::decode_qr_data(const std::string& qr_text,
                                          const std::string& share_password) {
    QRCodeData data;

    // Remove QR code formatting and get the raw data
    std::string raw_data = qr_text;

    // Remove ASCII QR formatting if present
    size_t start = raw_data.find("=== QR Code Pattern ===");
    if (start != std::string::npos) {
        size_t end = raw_data.find("=== End QR Pattern ===");
        if (end != std::string::npos) {
            raw_data = raw_data.substr(start + 24, end - start - 24);
        }
    }

    // Decrypt if share password is provided
    if (!share_password.empty()) {
        raw_data = decrypt_qr_data(raw_data, share_password);
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
        }
    }

    return data;
}

std::string QRCodeGenerator::generate_shareable_text(const QRCodeData& data) {
    std::stringstream ss;
    ss << "PASSWORD_SHARE_V1\n";
    ss << "SERVICE:" << data.service << "\n";
    ss << "USERNAME:" << data.username << "\n";
    ss << "PASSWORD:" << data.password << "\n";
    ss << "NOTES:" << data.notes << "\n";
    ss << "CATEGORY:" << data.category << "\n";
    ss << "EXPIRY:" << data.expiry_date << "\n";
    ss << "SHARE_ID:" << data.share_id << "\n";
    ss << "CREATED:" << data.created_timestamp << "\n";
    ss << "EXPIRES_AT:" << data.expires_at << "\n";
    ss << "END_SHARE";

    return ss.str();
}

std::string QRCodeGenerator::create_qr_pattern(const std::string& data) {
    try {
        // Generate online QR code URL
        std::string qr_url = generate_qr_url(data);

        // Save QR data to file for manual conversion
        std::string filename = "password_qr_" + generate_share_id() + ".txt";
        std::ofstream qr_file(filename);
        if (qr_file.is_open()) {
            qr_file << "QR Code Data for Password Sharing\n";
            qr_file << "==================================\n\n";
            qr_file << "Data to encode in QR code:\n";
            qr_file << data << "\n\n";
            qr_file << "Online QR Code Generator URL:\n";
            qr_file << qr_url << "\n\n";
            qr_file << "Instructions:\n";
            qr_file << "1. Copy the data above\n";
            qr_file << "2. Visit the URL above\n";
            qr_file << "3. Paste the data and generate QR code\n";
            qr_file << "4. Download or scan the generated QR code\n";
            qr_file.close();
        }

        std::stringstream result;
        result << "=== PASSWORD SHARING QR CODE ===\n";
        result << "✅ QR Code data saved as: " << filename << "\n";
        result << "🌐 Online QR Code URL: " << qr_url << "\n";
        result << "📱 Instructions:\n";
        result << "   1. Open the text file to get the data\n";
        result << "   2. Visit the URL above to generate QR code\n";
        result << "   3. Copy the data and paste it in the online generator\n";
        result << "   4. Download the generated QR code image\n";
        result << "   5. Scan with any QR code reader app\n";
        result << "\n📄 QR Code Data:\n";
        result << data << "\n";

        return result.str();

    } catch (const std::exception& e) {
        return "Error generating QR code: " + std::string(e.what()) + "\n";
    }
}

std::string QRCodeGenerator::create_ascii_qr(const std::string& data) {
    std::string result = "\n=== ASCII QR Pattern (Backup) ===\n";
    result += "This is a text representation for manual entry:\n\n";

    // Create a simple ASCII art QR-like pattern
    std::string encoded = base64_encode(std::vector<unsigned char>(data.begin(), data.end()));

    // Split into chunks and create a grid pattern
    int chunk_size = 8;
    int max_width = 40;

    result += "┌";
    for (int i = 0; i < max_width; ++i) result += "─";
    result += "┐\n";

    for (size_t i = 0; i < encoded.length(); i += chunk_size) {
        std::string chunk = encoded.substr(i, chunk_size);
        result += "│ ";
        result += chunk;

        // Pad with spaces
        int padding = max_width - chunk.length() - 2;
        for (int j = 0; j < padding; ++j) result += " ";
        result += " │\n";
    }

    result += "└";
    for (int i = 0; i < max_width; ++i) result += "─";
    result += "┘\n";

    result += "\n=== End ASCII Pattern ===\n";
    return result;
}

bool QRCodeGenerator::validate_qr_data(const QRCodeData& data) {
    // Check if required fields are present
    if (data.service.empty() || data.username.empty() || data.password.empty()) {
        return false;
    }

    // Check if QR code is expired
    if (!data.expires_at.empty() && is_qr_expired(data.expires_at)) {
        return false;
    }

    return true;
}

std::string QRCodeGenerator::generate_share_id() {
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

bool QRCodeGenerator::is_qr_expired(const std::string& expires_at) {
    if (expires_at.empty()) return false;

    std::tm tm = {};
    std::istringstream ss(expires_at);
    ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");

    if (ss.fail()) return false;

    time_t expiry_time = std::mktime(&tm);
    time_t now = time(nullptr);

    return now > expiry_time;
}

std::string QRCodeGenerator::encrypt_qr_data(const std::string& data, const std::string& key) {
    return simple_xor_encrypt(data, key);
}

std::string QRCodeGenerator::decrypt_qr_data(const std::string& encrypted_data, const std::string& key) {
    return simple_xor_decrypt(encrypted_data, key);
}

bool QRCodeGenerator::save_qr_to_file(const std::string& qr_data, const std::string& filename) {
    try {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << "QR Code Data:\n";
            file << qr_data << "\n\n";
            file << "Online QR Code Generator URL:\n";
            file << generate_qr_url(qr_data) << "\n";
            file.close();
            return true;
        }
        return false;
    } catch (const std::exception& e) {
        return false;
    }
}

std::string QRCodeGenerator::generate_qr_url(const std::string& data) {
    std::string base = "https://api.qrserver.com/v1/create-qr-code/?size=300x300&data=";
    return base + url_encode(data);
}

std::string QRCodeGenerator::base64_encode(const std::vector<unsigned char>& data) {
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

std::vector<unsigned char> QRCodeGenerator::base64_decode(const std::string& encoded) {
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

std::string QRCodeGenerator::simple_xor_encrypt(const std::string& data, const std::string& key) {
    if (key.empty()) return data;

    std::string result;
    for (size_t i = 0; i < data.length(); ++i) {
        result += data[i] ^ key[i % key.length()];
    }

    return base64_encode(std::vector<unsigned char>(result.begin(), result.end()));
}

std::string QRCodeGenerator::simple_xor_decrypt(const std::string& encrypted_data, const std::string& key) {
    if (key.empty()) return encrypted_data;

    std::vector<unsigned char> decoded = base64_decode(encrypted_data);
    std::string result;

    for (size_t i = 0; i < decoded.size(); ++i) {
        result += decoded[i] ^ key[i % key.length()];
    }

    return result;
}

std::string QRCodeGenerator::create_simple_qr_matrix(const std::string& data) {
    // Create a simple text representation of the QR code data
    std::stringstream ss;
    ss << "QR Code Data Matrix:\n";
    ss << "===================\n";
    ss << "Data Length: " << data.length() << " characters\n";
    ss << "Data: " << data << "\n";
    return ss.str();
}

std::string QRCodeGenerator::url_encode(const std::string& data) {
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

// Mobile Companion: Export/Import via QR code (string-based for demo)

std::string QRCodeMobile::export_to_qr(const std::string& password_data) {
    // For demo: just base64 encode the data
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -6;
    for (unsigned char c : password_data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}

std::string QRCodeMobile::import_from_qr(const std::string& qr_data) {
    // For demo: base64 decode
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int val = 0, valb = -8;
    for (char c : qr_data) {
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
