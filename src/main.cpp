#include "../include/password_manager.h"
#include "../include/password_strength.h"
#include "../include/utils.h"
#include "../include/advanced_encryption.h"
#include "../include/two_factor_auth.h"
#include "../include/smart_categories.h"
#include "../include/password_history.h"
#include "../include/self_destruct.h"
#include "../include/password_recovery.h"
#include "../include/qr_code.h"
#include <iostream>
#include <string>
#include <limits>
#include <ctime>
#include <vector>
#include <map>
#include <iomanip>

void show_main_menu() {
    std::cout << "\n==============================\n";
    std::cout << "🔐 Password Manager - Main Menu\n";
    std::cout << "==============================\n";
    std::cout << "1. Add Password\n";
    std::cout << "2. Get Password\n";
    std::cout << "3. Update Password\n";
    std::cout << "4. Delete Password\n";
    std::cout << "5. List All Passwords\n";
    std::cout << "6. Categories & Tags\n";
    std::cout << "7. Password History\n";
    std::cout << "8. Password Strength Checker\n";
    std::cout << "9. Two-Factor Authentication (2FA)\n";
    std::cout << "10. Password Sharing & Mobile Export\n";
    std::cout << "11. Password Recovery\n";
    std::cout << "12. Settings\n";
    std::cout << "13. Help/About\n";
    std::cout << "0. Exit\n";
    std::cout << "==============================\n";
    std::cout << "Enter your choice: ";
}

void onboarding() {
    std::cout << "\nWelcome to the Advanced Password Manager!\n";
    std::cout << "Let's set up your master password and recovery options.\n";
    // ... onboarding logic for master password, 2FA, recovery, etc. ...
}

void show_help() {
    std::cout << "\n=== Help & About ===\n";
    std::cout << "This is an advanced CLI password manager with:\n";
    std::cout << "- AES-256 encryption\n";
    std::cout << "- Two-Factor Authentication (2FA)\n";
    std::cout << "- Smart categories & tags\n";
    std::cout << "- Password history & versioning\n";
    std::cout << "- Self-destruct mode\n";
    std::cout << "- Mobile companion (QR/file export)\n";
    std::cout << "- Password strength visualization\n";
    std::cout << "- Secure recovery options\n";
    std::cout << "- And more!\n";
    std::cout << "\nFor more info, see the README or use the menu options.\n";
}

void show_settings() {
    std::cout << "\n=== Settings ===\n";
    std::cout << "(Feature toggles, thresholds, and preferences go here.)\n";
    // ... settings logic ...
}

void add_password(PasswordManager& pm) {
    std::string service, username, password, notes, category, expiry_date;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    std::cout << "Enter password: ";
    password = Utils::get_hidden_input("");

    std::cout << "Enter notes (optional): ";
    std::getline(std::cin, notes);

    std::cout << "Enter category (optional): ";
    std::getline(std::cin, category);

    std::cout << "Enter expiry date (YYYY-MM-DD, optional): ";
    std::getline(std::cin, expiry_date);

    pm.add_password(service, username, password, notes, category, expiry_date);
}

void get_password(PasswordManager& pm) {
    std::string service, username;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    // Get all passwords for this service
    auto all_passwords = pm.get_all_passwords();
    std::vector<std::string> usernames_for_service;

    for (const auto& entry : all_passwords) {
        if (entry.service == service) {
            usernames_for_service.push_back(entry.username);
        }
    }

    if (usernames_for_service.empty()) {
        std::cout << "No passwords found for service: " << service << "\n";
        return;
    }

    // Display all usernames for this service
    std::cout << "\nUsernames for " << service << ":\n";
    for (size_t i = 0; i < usernames_for_service.size(); ++i) {
        std::cout << (i + 1) << ". " << usernames_for_service[i] << "\n";
    }

    // Ask user to select username
    std::cout << "Enter username number or username: ";
    std::string choice;
    std::getline(std::cin, choice);

    // Check if user entered a number
    try {
        int choice_num = std::stoi(choice);
        if (choice_num >= 1 && choice_num <= static_cast<int>(usernames_for_service.size())) {
            username = usernames_for_service[choice_num - 1];
        } else {
            std::cout << "Invalid number. Please enter a valid username.\n";
            return;
        }
    } catch (...) {
        // User entered text, use it as username
        username = choice;
    }

    PasswordEntry* entry = pm.get_password(service, username);
    if (entry) {
        std::cout << "\n=== Password Details ===\n";
        std::cout << "Service: " << entry->service << "\n";
        std::cout << "Username: " << entry->username << "\n";
        std::cout << "Password: " << entry->password << "\n";
        if (!entry->notes.empty()) {
            std::cout << "Notes: " << entry->notes << "\n";
        }
        if (!entry->category.empty()) {
            std::cout << "Category: " << entry->category << "\n";
        }
        if (!entry->expiry_date.empty()) {
            int days_left = AdvancedFeatures::days_until_expiry(entry->expiry_date);
            std::cout << "Expiry Date: " << entry->expiry_date;
            if (days_left > 0) {
                std::cout << " (expires in " << days_left << " days)";
            } else if (days_left == 0) {
                std::cout << " (expires today!)";
            } else {
                std::cout << " (EXPIRED " << -days_left << " days ago!)";
            }
            std::cout << "\n";
        }
        std::cout << "Created: " << entry->created_date << "\n";
        std::cout << "Modified: " << entry->modified_date << "\n";
        std::cout << "Favorite: " << (entry->is_favorite ? "Yes" : "No") << "\n";
    }
}

void update_password(PasswordManager& pm) {
    std::string service, username, new_password, notes, category, expiry_date;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    std::cout << "Enter new password: ";
    new_password = Utils::get_hidden_input("");

    std::cout << "Enter new notes (optional): ";
    std::getline(std::cin, notes);

    std::cout << "Enter category (optional): ";
    std::getline(std::cin, category);

    std::cout << "Enter expiry date (YYYY-MM-DD, optional): ";
    std::getline(std::cin, expiry_date);

    pm.update_password(service, username, new_password, notes, category, expiry_date);
}

void delete_password(PasswordManager& pm) {
    std::string service, username;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    std::cout << "Are you sure you want to delete this password? (y/N): ";
    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm == "y" || confirm == "Y") {
        pm.delete_password(service, username);
    } else {
        std::cout << "Deletion cancelled.\n";
    }
}

void search_passwords(PasswordManager& pm) {
    std::string search_term, category;

    std::cout << "Enter search term: ";
    std::getline(std::cin, search_term);

    std::cout << "Enter category to filter (optional): ";
    std::getline(std::cin, category);

    auto results = pm.search_passwords(search_term);

    if (results.empty()) {
        std::cout << "No passwords found.\n";
    } else {
        std::cout << "\n=== Search Results ===\n";
        for (const auto& entry : results) {
            std::cout << "Service: " << entry.service << " | Username: " << entry.username;
            if (!entry.category.empty()) {
                std::cout << " | Category: " << entry.category;
            }
            if (entry.is_favorite) {
                std::cout << " | ⭐";
            }
            std::cout << "\n";
        }
    }
}

void list_all_passwords(PasswordManager& pm) {
    auto passwords = pm.get_all_passwords();

    if (passwords.empty()) {
        std::cout << "No passwords stored.\n";
    } else {
        std::cout << "\n=== All Passwords ===\n";
        for (const auto& entry : passwords) {
            std::cout << "Service: " << entry.service << " | Username: " << entry.username;
            if (!entry.category.empty()) {
                std::cout << " | Category: " << entry.category;
            }
            if (entry.is_favorite) {
                std::cout << " | ⭐";
            }
            std::cout << "\n";
        }
    }
}

void check_password_strength() {
    std::string password = Utils::get_hidden_input("Enter password to check: ");
    AdvancedFeatures::display_password_strength_visual(password);
}

void generate_strong_password() {
    std::cout << "=== Advanced Password Generator ===\n";

    PasswordGeneratorRules rules;

    std::cout << "Enter password length (default 16): ";
    std::string length_str;
    std::getline(std::cin, length_str);
    if (!length_str.empty()) {
        try {
            rules.length = std::stoi(length_str);
        } catch (...) {
            std::cout << "Invalid length, using default 16.\n";
        }
    }

    std::cout << "Include uppercase letters? (y/n, default y): ";
    std::string choice;
    std::getline(std::cin, choice);
    rules.use_uppercase = (choice.empty() || choice == "y" || choice == "Y");

    std::cout << "Include lowercase letters? (y/n, default y): ";
    std::getline(std::cin, choice);
    rules.use_lowercase = (choice.empty() || choice == "y" || choice == "Y");

    std::cout << "Include digits? (y/n, default y): ";
    std::getline(std::cin, choice);
    rules.use_digits = (choice.empty() || choice == "y" || choice == "Y");

    std::cout << "Include symbols? (y/n, default y): ";
    std::getline(std::cin, choice);
    rules.use_symbols = (choice.empty() || choice == "y" || choice == "Y");

    std::cout << "Exclude similar characters (0,O,1,l,I)? (y/n, default n): ";
    std::getline(std::cin, choice);
    rules.exclude_similar = (choice == "y" || choice == "Y");

    std::string password = AdvancedFeatures::generate_password_with_rules(rules);
    std::cout << "Generated password: " << password << "\n";

    // Show strength analysis
    AdvancedFeatures::display_password_strength_visual(password);
}

void change_master_password(PasswordManager& pm) {
    std::string old_password = Utils::get_hidden_input("Enter current master password: ");
    std::string new_password = Utils::get_hidden_input("Enter new master password: ");
    std::string confirm_password = Utils::get_hidden_input("Confirm new master password: ");

    if (new_password != confirm_password) {
        std::cout << "New passwords don't match!\n";
        return;
    }

    pm.change_master_password(old_password, new_password);
}

void password_expiry_management(PasswordManager& pm) {
    std::cout << "\n=== Password Expiry Management ===\n";
    std::cout << "1. View expired passwords\n";
    std::cout << "2. View passwords expiring soon\n";
    std::cout << "3. Update password expiry\n";
    std::cout << "Enter choice: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        auto expired = pm.get_expired_passwords_public();
        if (expired.empty()) {
            std::cout << "No expired passwords found.\n";
        } else {
            std::cout << "\n=== Expired Passwords ===\n";
            for (const auto& entry : expired) {
                std::cout << "Service: " << entry.service << " | Username: " << entry.username;
                std::cout << " | Expired: " << entry.expiry_date << "\n";
            }
        }
    } else if (choice == "2") {
        std::cout << "Enter days threshold (default 30): ";
        std::string days_str;
        std::getline(std::cin, days_str);
        int days = 30;
        if (!days_str.empty()) {
            try {
                days = std::stoi(days_str);
            } catch (...) {
                std::cout << "Invalid input, using 30 days.\n";
            }
        }

        auto expiring = pm.get_expiring_soon_passwords_public(days);
        if (expiring.empty()) {
            std::cout << "No passwords expiring in the next " << days << " days.\n";
        } else {
            std::cout << "\n=== Passwords Expiring Soon ===\n";
            for (const auto& entry : expiring) {
                int days_left = AdvancedFeatures::days_until_expiry(entry.expiry_date);
                std::cout << "Service: " << entry.service << " | Username: " << entry.username;
                std::cout << " | Expires: " << entry.expiry_date << " (in " << days_left << " days)\n";
            }
        }
    } else if (choice == "3") {
        std::string service, username, new_expiry;
        std::cout << "Enter service name: ";
        std::getline(std::cin, service);
        std::cout << "Enter username: ";
        std::getline(std::cin, username);
        std::cout << "Enter new expiry date (YYYY-MM-DD): ";
        std::getline(std::cin, new_expiry);

        if (pm.update_password_expiry(service, username, new_expiry)) {
            std::cout << "Expiry date updated successfully!\n";
        }
    }
}

void password_history(PasswordManager& pm) {
    std::string service, username;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    auto history = pm.get_password_history(service, username);
    if (history.empty()) {
        std::cout << "No password history found for this account.\n";
    } else {
        std::cout << "\n=== Password History ===\n";
        for (size_t i = 0; i < history.size(); ++i) {
            std::cout << (i + 1) << ". " << std::string(history[i].length(), '*') << "\n";
        }
    }
}

void generate_qr_code(PasswordManager& pm) {
    std::string service, username;

    std::cout << "Enter service name: ";
    std::getline(std::cin, service);

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    PasswordEntry* entry = pm.get_password(service, username);
    if (entry) {
        QRCodeData data;
        data.service = entry->service;
        data.username = entry->username;
        data.password = entry->password;
        data.notes = entry->notes;
        data.category = entry->category;
        data.expiry_date = entry->expiry_date;

        std::string qr_text = AdvancedFeatures::generate_qr_code_text(data);
        std::cout << qr_text << "\n";

        std::cout << "QR code generated! Scan with your mobile device.\n";
    } else {
        std::cout << "Password not found.\n";
    }
}

void check_password_breach() {
    std::string password = Utils::get_hidden_input("Enter password to check: ");

    std::cout << "\n=== Breach Check ===\n";
    std::cout << "Checking password against breach databases...\n";

    auto result = AdvancedFeatures::check_password_breach(password);

    if (result.is_breached) {
        std::cout << "🔴 WARNING: This password has been compromised!\n";
        std::cout << "Found in " << result.breach_count << " breach(es).\n";
        std::cout << "Sources: ";
        for (const auto& source : result.breach_sources) {
            std::cout << source << " ";
        }
        std::cout << "\n";
        std::cout << "Recommendation: Change this password immediately!\n";
    } else {
        std::cout << "🟢 Good news! This password hasn't been found in known breaches.\n";
    }

    std::cout << "Last checked: " << result.last_check_date << "\n";
}

void password_health_analysis(PasswordManager& pm) {
    auto passwords = pm.get_all_passwords();

    if (passwords.empty()) {
        std::cout << "No passwords to analyze.\n";
        return;
    }

    std::cout << "\n=== Password Health Analysis ===\n";

    double health_score = AdvancedFeatures::calculate_password_health_score(passwords);
    std::string rating = AdvancedFeatures::get_health_rating(health_score);

    std::cout << "Overall Health Score: " << std::fixed << std::setprecision(1) << health_score << "/100\n";
    std::cout << "Rating: " << rating << "\n";

    // Find duplicates
    auto duplicates = pm.find_duplicate_passwords();
    if (!duplicates.empty()) {
        std::cout << "\n⚠️  Found " << duplicates.size() << " duplicate password(s):\n";
        for (const auto& dup : duplicates) {
            std::cout << "  - " << dup.first << " and " << dup.second << "\n";
        }
    }

    // Check expired passwords
    auto expired = pm.get_expired_passwords_public();
    if (!expired.empty()) {
        std::cout << "\n⚠️  Found " << expired.size() << " expired password(s)\n";
    }

    // Category distribution
    std::map<std::string, int> category_count;
    for (const auto& entry : passwords) {
        std::string cat = entry.category.empty() ? "Uncategorized" : entry.category;
        category_count[cat]++;
    }

    std::cout << "\nCategory Distribution:\n";
    for (const auto& cat : category_count) {
        std::cout << "  " << cat.first << ": " << cat.second << " password(s)\n";
    }
}

void manage_categories(PasswordManager& pm) {
    std::cout << "\n=== Category Management ===\n";
    std::cout << "1. View all categories\n";
    std::cout << "2. Search by category\n";
    std::cout << "Enter choice: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        auto categories = pm.get_all_categories();
        if (categories.empty()) {
            std::cout << "No categories found.\n";
        } else {
            std::cout << "\n=== All Categories ===\n";
            for (const auto& cat : categories) {
                std::cout << "- " << cat << "\n";
            }
        }
    } else if (choice == "2") {
        std::string category;
        std::cout << "Enter category name: ";
        std::getline(std::cin, category);

        auto results = pm.search_passwords_by_category(category);
        if (results.empty()) {
            std::cout << "No passwords found in category: " << category << "\n";
        } else {
            std::cout << "\n=== Passwords in " << category << " ===\n";
            for (const auto& entry : results) {
                std::cout << "Service: " << entry.service << " | Username: " << entry.username << "\n";
            }
        }
    }
}

void find_duplicate_passwords(PasswordManager& pm) {
    auto duplicates = pm.find_duplicate_passwords();

    if (duplicates.empty()) {
        std::cout << "No duplicate passwords found. Great job!\n";
    } else {
        std::cout << "\n=== Duplicate Passwords Found ===\n";
        std::cout << "The following accounts use the same password:\n";
        for (const auto& dup : duplicates) {
            std::cout << "  - " << dup.first << " and " << dup.second << "\n";
        }
        std::cout << "\nRecommendation: Change these passwords to unique ones.\n";
    }
}

void favorites_management(PasswordManager& pm) {
    std::cout << "\n=== Favorites Management ===\n";
    std::cout << "1. View favorite passwords\n";
    std::cout << "2. Toggle favorite status\n";
    std::cout << "Enter choice: ";

    std::string choice;
    std::getline(std::cin, choice);

    if (choice == "1") {
        auto favorites = pm.get_favorite_passwords();
        if (favorites.empty()) {
            std::cout << "No favorite passwords found.\n";
        } else {
            std::cout << "\n=== Favorite Passwords ===\n";
            for (const auto& entry : favorites) {
                std::cout << "⭐ " << entry.service << " | " << entry.username << "\n";
            }
        }
    } else if (choice == "2") {
        std::string service, username;
        std::cout << "Enter service name: ";
        std::getline(std::cin, service);
        std::cout << "Enter username: ";
        std::getline(std::cin, username);

        if (pm.toggle_favorite(service, username)) {
            std::cout << "Favorite status updated!\n";
        }
    }
}

int main() {
    srand(time(0)); // Initialize random seed

    PasswordManager pm;

    try {
        if (!pm.initialize()) {
            std::cout << "Failed to initialize password manager.\n";
            return 1;
        }

        // Login loop
        while (!pm.is_logged_in()) {
            std::string master_password = Utils::get_hidden_input("Enter master password: ");
            if (pm.login(master_password)) {
                std::cout << "Login successful!\n";
            } else {
                std::cout << "Invalid master password. Please try again.\n";
            }
        }

        // Onboarding for first-time users
        onboarding();

        // Main application loop
        while (pm.is_logged_in()) {
            int choice;
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
                    update_password(pm);
                    break;
                case 4:
                    delete_password(pm);
                    break;
                case 5:
                    list_all_passwords(pm);
                    break;
                case 6:
                    manage_categories(pm);
                    break;
                case 7:
                    password_history(pm);
                    break;
                case 8:
                    check_password_strength();
                    break;
                case 9:
                    // ... 2FA logic ...
                    break;
                case 10:
                    // ... sharing/mobile logic ...
                    break;
                case 11:
                    // ... recovery logic ...
                    break;
                case 12:
                    show_settings();
                    break;
                case 13:
                    show_help();
                    break;
                case 0:
                    pm.logout();
                    std::cout << "Logged out successfully.\n";
                    return 0;
                default:
                    std::cout << "Invalid choice. Please try again.\n";
            }
        }

    } catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
