#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <chrono>
#include <set>

struct PasswordEntry {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string created_date;
    std::string modified_date;
    std::string expiry_date;           // New: Password expiry date
    std::string category;              // New: Password category/tag
    bool is_favorite;                  // New: Mark as favorite
    std::vector<std::string> password_history; // New: Password history
    std::string totp_secret;           // New: 2FA secret (for future use)
};

struct PasswordGeneratorRules {
    int length = 16;
    bool use_uppercase = true;
    bool use_lowercase = true;
    bool use_digits = true;
    bool use_symbols = true;
    bool exclude_similar = false;      // Exclude 0,O,1,l,I, etc.
    std::string custom_chars = "";     // Custom character set
};

struct BreachCheckResult {
    bool is_breached = false;
    int breach_count = 0;
    std::vector<std::string> breach_sources;
    std::string last_check_date;
};

class PasswordManager {
private:
    std::unordered_map<std::string, PasswordEntry> passwords;
    std::string master_password_hash;
    std::string data_file_path;
    bool is_authenticated;
    std::set<std::string> categories;  // Track all categories

    bool authenticate_user();
    void save_passwords_to_file();
    void load_passwords_from_file();
    std::string hash_password(const std::string& password);
    bool verify_password_hash(const std::string& password, const std::string& hash);

    // New helper methods
    void add_to_password_history(const std::string& key, const std::string& old_password);
    std::vector<PasswordEntry> search_passwords_advanced(const std::string& search_term, const std::string& category = "");
    bool is_password_expired(const std::string& expiry_date);
    std::vector<PasswordEntry> get_expired_passwords();
    std::vector<PasswordEntry> get_expiring_soon_passwords(int days = 30);

public:
    PasswordManager(const std::string& file_path = "passwords.dat");

    bool initialize();
    bool login(const std::string& master_password);
    bool change_master_password(const std::string& old_password, const std::string& new_password);

    // Core password operations
    bool add_password(const std::string& service, const std::string& username,
                     const std::string& password, const std::string& notes = "",
                     const std::string& category = "", const std::string& expiry_date = "");
    bool update_password(const std::string& service, const std::string& username,
                        const std::string& new_password, const std::string& notes = "",
                        const std::string& category = "", const std::string& expiry_date = "");
    bool delete_password(const std::string& service, const std::string& username);

    PasswordEntry* get_password(const std::string& service, const std::string& username);
    std::vector<PasswordEntry> search_passwords(const std::string& search_term);
    std::vector<PasswordEntry> get_all_passwords();

    // New advanced features
    std::vector<PasswordEntry> search_passwords_by_category(const std::string& category);
    std::vector<std::string> get_all_categories();
    std::vector<PasswordEntry> get_favorite_passwords();
    bool toggle_favorite(const std::string& service, const std::string& username);

    // Password expiry features
    std::vector<PasswordEntry> get_expired_passwords_public();
    std::vector<PasswordEntry> get_expiring_soon_passwords_public(int days = 30);
    bool update_password_expiry(const std::string& service, const std::string& username,
                               const std::string& new_expiry_date);

    // Password history
    std::vector<std::string> get_password_history(const std::string& service, const std::string& username);

    // Duplicate detection
    std::vector<std::pair<std::string, std::string>> find_duplicate_passwords();

    bool is_logged_in() const { return is_authenticated; }
    void logout() { is_authenticated = false; }
};
