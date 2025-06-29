#include "../include/advanced_features.h"
#include "../include/password_strength.h"
#include "../include/utils.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <map>

std::string AdvancedFeatures::generate_password_with_rules(const PasswordGeneratorRules& rules) {
    std::string charset = "";

    if (rules.use_lowercase) charset += "abcdefghijklmnopqrstuvwxyz";
    if (rules.use_uppercase) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (rules.use_digits) charset += "0123456789";
    if (rules.use_symbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    if (!rules.custom_chars.empty()) charset += rules.custom_chars;

    if (charset.empty()) {
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    }

    // Remove similar characters if requested
    if (rules.exclude_similar) {
        std::string similar_chars = "0O1lI5S8B";
        for (char c : similar_chars) {
            charset.erase(std::remove(charset.begin(), charset.end(), c), charset.end());
        }
    }

    std::string password;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, charset.length() - 1);

    // Ensure at least one character from each required type
    if (rules.use_lowercase && charset.find_first_of("abcdefghijklmnopqrstuvwxyz") != std::string::npos) {
        std::string lower = "abcdefghijklmnopqrstuvwxyz";
        password += lower[dis(gen) % lower.length()];
    }
    if (rules.use_uppercase && charset.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos) {
        std::string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        password += upper[dis(gen) % upper.length()];
    }
    if (rules.use_digits && charset.find_first_of("0123456789") != std::string::npos) {
        std::string digits = "0123456789";
        password += digits[dis(gen) % digits.length()];
    }
    if (rules.use_symbols && charset.find_first_of("!@#$%^&*()_+-=[]{}|;:,.<>?") != std::string::npos) {
        std::string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        password += symbols[dis(gen) % symbols.length()];
    }

    // Fill the rest with random characters
    while (password.length() < rules.length) {
        password += charset[dis(gen)];
    }

    // Shuffle the password
    std::shuffle(password.begin(), password.end(), gen);

    return password.substr(0, rules.length);
}

void AdvancedFeatures::display_password_strength_visual(const std::string& password) {
    auto result = PasswordStrengthChecker::check_strength(password);

    std::cout << "\n=== Password Strength Visualization ===\n";
    std::cout << "Password: " << std::string(password.length(), '*') << "\n";
    std::cout << "Score: " << result.score << "/100\n";

    // Visual strength bar
    std::cout << "Strength: [";
    int bar_length = 20;
    int filled_length = (result.score * bar_length) / 100;

    std::string color = get_strength_color_code(result.strength);
    for (int i = 0; i < bar_length; ++i) {
        if (i < filled_length) {
            std::cout << "█";
        } else {
            std::cout << "░";
        }
    }
    std::cout << "]\n";

    std::cout << "Rating: ";
    switch (result.strength) {
        case PasswordStrength::VERY_WEAK: std::cout << "🔴 Very Weak"; break;
        case PasswordStrength::WEAK: std::cout << "🟠 Weak"; break;
        case PasswordStrength::MEDIUM: std::cout << "🟡 Medium"; break;
        case PasswordStrength::STRONG: std::cout << "🟢 Strong"; break;
        case PasswordStrength::VERY_STRONG: std::cout << "🟢 Very Strong"; break;
    }
    std::cout << "\n";
    std::cout << "Feedback: " << result.feedback << "\n";
}

std::string AdvancedFeatures::get_strength_color_code(PasswordStrength strength) {
    switch (strength) {
        case PasswordStrength::VERY_WEAK: return "red";
        case PasswordStrength::WEAK: return "orange";
        case PasswordStrength::MEDIUM: return "yellow";
        case PasswordStrength::STRONG: return "green";
        case PasswordStrength::VERY_STRONG: return "bright_green";
        default: return "white";
    }
}

std::string AdvancedFeatures::generate_qr_code_text(const QRCodeData& data) {
    std::stringstream ss;
    ss << "PASSWORD_MANAGER_QR\n";
    ss << "Service: " << data.service << "\n";
    ss << "Username: " << data.username << "\n";
    ss << "Password: " << data.password << "\n";
    if (!data.notes.empty()) ss << "Notes: " << data.notes << "\n";
    if (!data.category.empty()) ss << "Category: " << data.category << "\n";
    if (!data.expiry_date.empty()) ss << "Expiry: " << data.expiry_date << "\n";

    return create_simple_qr_pattern(ss.str());
}

std::string AdvancedFeatures::generate_password_qr_text(const std::string& service,
                                                       const std::string& username,
                                                       const std::string& password) {
    QRCodeData data;
    data.service = service;
    data.username = username;
    data.password = password;
    return generate_qr_code_text(data);
}

std::string AdvancedFeatures::create_simple_qr_pattern(const std::string& data) {
    // Simple text-based QR representation
    std::string result = "\n=== QR Code Pattern ===\n";
    result += "Scan this pattern with a QR code reader:\n\n";

    // Create a simple ASCII art QR-like pattern
    std::string encoded = Utils::base64_encode(std::vector<unsigned char>(data.begin(), data.end()));

    // Split into chunks and create a grid
    int chunk_size = 8;
    for (size_t i = 0; i < encoded.length(); i += chunk_size) {
        std::string chunk = encoded.substr(i, chunk_size);
        result += "█" + chunk + "█\n";
    }

    result += "\n=== End QR Pattern ===\n";
    return result;
}

BreachCheckResult AdvancedFeatures::check_password_breach(const std::string& password) {
    BreachCheckResult result;
    result.last_check_date = Utils::get_current_timestamp();

    // Simulated breach check (in real implementation, this would use HaveIBeenPwned API)
    std::vector<std::string> common_breached = get_common_breached_passwords();

    for (const auto& breached_pwd : common_breached) {
        if (password == breached_pwd) {
            result.is_breached = true;
            result.breach_count++;
            result.breach_sources.push_back("Common breached passwords database");
        }
    }

    // Check for very weak patterns
    if (password.length() < 6 ||
        password == "password" ||
        password == "123456" ||
        password == "qwerty") {
        result.is_breached = true;
        result.breach_count++;
        result.breach_sources.push_back("Common weak password patterns");
    }

    return result;
}

std::vector<std::string> AdvancedFeatures::get_common_breached_passwords() {
    return {
        "password", "123456", "123456789", "qwerty", "abc123",
        "password123", "admin", "letmein", "welcome", "monkey",
        "1234567890", "dragon", "baseball", "football", "shadow"
    };
}

std::string AdvancedFeatures::generate_shareable_qr_text(const QRCodeData& data,
                                                        const std::string& share_password) {
    std::stringstream ss;
    ss << "SHARED_PASSWORD_QR\n";
    ss << "Encrypted: true\n";
    if (!share_password.empty()) {
        ss << "Protected: true\n";
    }
    ss << "Service: " << data.service << "\n";
    ss << "Username: " << data.username << "\n";
    ss << "Password: " << data.password << "\n";
    if (!data.notes.empty()) ss << "Notes: " << data.notes << "\n";

    return create_simple_qr_pattern(ss.str());
}

QRCodeData AdvancedFeatures::decode_shared_qr_text(const std::string& qr_text,
                                                   const std::string& share_password) {
    QRCodeData data;
    // Simple parsing (in real implementation, this would parse the QR data properly)
    std::istringstream iss(qr_text);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.find("Service: ") == 0) {
            data.service = line.substr(9);
        } else if (line.find("Username: ") == 0) {
            data.username = line.substr(10);
        } else if (line.find("Password: ") == 0) {
            data.password = line.substr(10);
        } else if (line.find("Notes: ") == 0) {
            data.notes = line.substr(7);
        }
    }

    return data;
}

double AdvancedFeatures::calculate_password_health_score(const std::vector<PasswordEntry>& passwords) {
    if (passwords.empty()) return 0.0;

    double total_score = 0.0;
    int valid_passwords = 0;

    for (const auto& entry : passwords) {
        auto strength = PasswordStrengthChecker::check_strength(entry.password);
        total_score += strength.score;
        valid_passwords++;
    }

    return valid_passwords > 0 ? total_score / valid_passwords : 0.0;
}

std::string AdvancedFeatures::get_health_rating(double score) {
    if (score >= 80) return "🟢 Excellent";
    if (score >= 60) return "🟡 Good";
    if (score >= 40) return "🟠 Fair";
    if (score >= 20) return "🔴 Poor";
    return "🔴 Very Poor";
}

std::string AdvancedFeatures::add_days_to_date(const std::string& date, int days) {
    // Simple date manipulation (in real implementation, use proper date library)
    if (date.empty()) return "";

    std::tm tm = {};
    std::istringstream ss(date);
    ss >> std::get_time(&tm, "%Y-%m-%d");

    if (ss.fail()) return date; // Return original if parsing fails

    // Add days
    std::time_t time = std::mktime(&tm);
    time += days * 24 * 60 * 60;
    tm = *std::localtime(&time);

    std::ostringstream result;
    result << std::put_time(&tm, "%Y-%m-%d");
    return result.str();
}

int AdvancedFeatures::days_until_expiry(const std::string& expiry_date) {
    if (expiry_date.empty()) return -1;

    std::tm tm = {};
    std::istringstream ss(expiry_date);
    ss >> std::get_time(&tm, "%Y-%m-%d");

    if (ss.fail()) return -1;

    std::time_t expiry_time = std::mktime(&tm);
    std::time_t now = std::time(nullptr);

    return static_cast<int>((expiry_time - now) / (24 * 60 * 60));
}

bool AdvancedFeatures::is_date_valid(const std::string& date) {
    if (date.empty()) return false;

    std::tm tm = {};
    std::istringstream ss(date);
    ss >> std::get_time(&tm, "%Y-%m-%d");

    return !ss.fail();
}
