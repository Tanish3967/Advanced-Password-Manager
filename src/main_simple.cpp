#include "../include/password_manager.h"
#include "../include/password_strength.h"
#include "../include/utils.h"
#include "../include/qr_code.h"
#include "../include/password_sharing.h"
#include <iostream>
#include <string>
#include <limits>
#include <ctime>
#include <vector>
#include <map>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <cstring>

// Simple encryption (XOR-based) for portability
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

// Password entry structure
struct PasswordEntry {
    std::string service;
    std::string username;
    std::string password;
    std::string notes;
    std::string category;
    std::string tags;
    time_t created_date;
    time_t expiry_date;
};

// Password Manager Class
class PasswordManager {
private:
    std::map<std::string, PasswordEntry> passwords;
    std::string master_password;
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

public:
    bool login(const std::string& password) {
        if (password == master_password) {
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
        entry.expiry_date = 0; // No expiry by default

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
        security_answer_hash = simple_hash(answer);
        std::cout << "✅ Security question set successfully.\n";
    }

    std::string get_security_question() const {
        return security_question;
    }

    bool validate_security_answer(const std::string& answer) {
        return simple_hash(answer) == security_answer_hash;
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

            file.close();
            std::cout << "✅ Passwords imported from " << filename << "\n";
        } else {
            std::cout << "❌ Failed to import passwords.\n";
        }
    }

    void setup_initial_config() {
        std::cout << "\n🎉 Welcome to Advanced Password Manager!\n";
        std::cout << "========================================\n";

        // Set master password
        std::cout << "Please set your master password: ";
        std::getline(std::cin, master_password);

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

    void trigger_self_destruct() {
        std::cout << "🚨 SELF-DESTRUCT MODE ACTIVATED!\n";
        std::cout << "Wiping all sensitive data...\n";

        // Overwrite and delete data file
        std::fstream file(data_file, std::ios::in | std::ios::out | std::ios::binary);
        if (file.is_open()) {
            file.seekg(0, std::ios::end);
            std::streampos length = file.tellg();
            file.seekp(0, std::ios::beg);
            for (size_t i = 0; i < static_cast<size_t>(length); ++i) {
                file.put(0);
            }
            file.close();
        }
        std::remove(data_file.c_str());

        std::cout << "✅ All data wiped. Exiting...\n";
        exit(0);
    }

    void save_data() {
        std::ofstream file(data_file);
        if (file.is_open()) {
            // Save master password hash
            file << "MASTER:" << simple_hash(master_password) << "\n";

            // Save passwords
            for (const auto& pair : passwords) {
                file << "PASSWORD:" << SimpleEncryption::encrypt(pair.second.service, master_password) << "\n";
                file << "USERNAME:" << SimpleEncryption::encrypt(pair.second.username, master_password) << "\n";
                file << "PASS:" << SimpleEncryption::encrypt(pair.second.password, master_password) << "\n";
                file << "NOTES:" << SimpleEncryption::encrypt(pair.second.notes, master_password) << "\n";
                file << "CATEGORY:" << SimpleEncryption::encrypt(pair.second.category, master_password) << "\n";
                file << "TAGS:" << SimpleEncryption::encrypt(pair.second.tags, master_password) << "\n";
                file << "CREATED:" << pair.second.created_date << "\n";
                file << "EXPIRY:" << pair.second.expiry_date << "\n";
                file << "---\n";
            }

            file.close();
        }
    }

    void load_data() {
        std::ifstream file(data_file);
        if (file.is_open()) {
            std::string line;
            std::string current_service, current_username, current_password, current_notes, current_category, current_tags;
            time_t current_created = 0, current_expiry = 0;
            bool in_password_block = false;

            while (std::getline(file, line)) {
                if (line == "---") {
                    if (in_password_block) {
                        add_password(current_service, current_username, current_password,
                                   current_notes, current_category, current_tags);
                        current_service = current_username = current_password = current_notes = current_category = current_tags = "";
                        current_created = current_expiry = 0;
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
                } else if (line.find("EXPIRY:") == 0) {
                    current_expiry = std::stol(line.substr(7));
                }
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
    std::cout << "11. Help/About\n";
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

    // Login
    std::string password;
    std::cout << "\n🔐 Login to Password Manager\n";
    std::cout << "===========================\n";
    std::cout << "Master Password: ";
    std::getline(std::cin, password);

    if (!pm.login(password)) {
        std::cout << "❌ Invalid password.\n";
        return 1;
    }

    std::cout << "✅ Login successful!\n";

    // Load data
    pm.load_data();

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
