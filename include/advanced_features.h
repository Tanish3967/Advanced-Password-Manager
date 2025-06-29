#pragma once

#include <string>
#include <vector>
#include <map>
#include <iomanip>
#include "password_strength.h"
#include "password_manager.h"

struct QRCodeData {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string category;
    std::string expiry_date;
};

struct PasswordGeneratorRules {
    int length = 16;
    bool use_uppercase = true;
    bool use_lowercase = true;
    bool use_digits = true;
    bool use_symbols = true;
    bool exclude_similar = false;
    std::string custom_chars = "";
};

struct BreachCheckResult {
    bool is_breached = false;
    int breach_count = 0;
    std::vector<std::string> breach_sources;
    std::string last_check_date;
};

class AdvancedFeatures {
public:
    // Enhanced password generation with custom rules
    static std::string generate_password_with_rules(const PasswordGeneratorRules& rules);

    // Password strength visualization
    static void display_password_strength_visual(const std::string& password);
    static std::string get_strength_color_code(PasswordStrength strength);

    // QR Code generation (text-based representation)
    static std::string generate_qr_code_text(const QRCodeData& data);
    static std::string generate_password_qr_text(const std::string& service,
                                                const std::string& username,
                                                const std::string& password);

    // Breach monitoring (simulated - in real implementation would use API)
    static BreachCheckResult check_password_breach(const std::string& password);
    static std::vector<std::string> get_common_breached_passwords();

    // Password sharing via QR
    static std::string generate_shareable_qr_text(const QRCodeData& data,
                                                 const std::string& share_password = "");
    static QRCodeData decode_shared_qr_text(const std::string& qr_text,
                                           const std::string& share_password = "");

    // Password health analysis
    static double calculate_password_health_score(const std::vector<PasswordEntry>& passwords);
    static std::string get_health_rating(double score);

    // Date utilities
    static std::string add_days_to_date(const std::string& date, int days);
    static int days_until_expiry(const std::string& expiry_date);
    static bool is_date_valid(const std::string& date);

private:
    static std::string create_simple_qr_pattern(const std::string& data);
    static std::string hash_for_breach_check(const std::string& password);
};
