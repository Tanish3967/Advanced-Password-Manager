#include "../include/password_manager.h"
#include "../include/simple_encryption.h"
#include "../include/utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <map>

PasswordManager::PasswordManager(const std::string& file_path)
    : data_file_path(file_path), is_authenticated(false) {
}

bool PasswordManager::initialize() {
    // Check if data file exists
    std::ifstream file(data_file_path);
    if (!file.good()) {
        // First time setup - create master password
        std::cout << "Welcome to Advanced Password Manager!\n";
        std::cout << "This is your first time setup. Please create a master password.\n";

        std::string master_pwd = Utils::get_hidden_input("Enter master password: ");
        std::string confirm_pwd = Utils::get_hidden_input("Confirm master password: ");

        if (master_pwd != confirm_pwd) {
            std::cout << "Passwords don't match!\n";
            return false;
        }

        master_password_hash = SimpleEncryption::hash_password(master_pwd);
        save_passwords_to_file();
        std::cout << "Master password created successfully!\n";
        return true;
    }

    file.close();
    return true;
}

bool PasswordManager::login(const std::string& master_password) {
    if (master_password_hash.empty()) {
        load_passwords_from_file();
    }

    if (SimpleEncryption::hash_password(master_password) == master_password_hash) {
        is_authenticated = true;
        return true;
    }
    return false;
}

bool PasswordManager::change_master_password(const std::string& old_password, const std::string& new_password) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    if (SimpleEncryption::hash_password(old_password) != master_password_hash) {
        std::cout << "Incorrect old password.\n";
        return false;
    }

    master_password_hash = SimpleEncryption::hash_password(new_password);
    save_passwords_to_file();
    std::cout << "Master password changed successfully!\n";
    return true;
}

bool PasswordManager::add_password(const std::string& service, const std::string& username,
                                 const std::string& password, const std::string& notes,
                                 const std::string& category, const std::string& expiry_date) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    std::string key = service + ":" + username;
    if (passwords.find(key) != passwords.end()) {
        std::cout << "Password for this service and username already exists.\n";
        return false;
    }

    PasswordEntry entry;
    entry.service = service;
    entry.username = username;
    entry.password = password;
    entry.notes = notes;
    entry.category = category;
    entry.expiry_date = expiry_date;
    entry.is_favorite = false;
    entry.created_date = Utils::get_current_timestamp();
    entry.modified_date = entry.created_date;

    passwords[key] = entry;
    if (!category.empty()) {
        categories.insert(category);
    }
    save_passwords_to_file();
    std::cout << "Password added successfully!\n";
    return true;
}

bool PasswordManager::update_password(const std::string& service, const std::string& username,
                                    const std::string& new_password, const std::string& notes,
                                    const std::string& category, const std::string& expiry_date) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return false;
    }

    // Add old password to history
    add_to_password_history(key, it->second.password);

    it->second.password = new_password;
    if (!notes.empty()) {
        it->second.notes = notes;
    }
    if (!category.empty()) {
        it->second.category = category;
        categories.insert(category);
    }
    if (!expiry_date.empty()) {
        it->second.expiry_date = expiry_date;
    }
    it->second.modified_date = Utils::get_current_timestamp();

    save_passwords_to_file();
    std::cout << "Password updated successfully!\n";
    return true;
}

bool PasswordManager::delete_password(const std::string& service, const std::string& username) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return false;
    }

    passwords.erase(it);
    save_passwords_to_file();
    std::cout << "Password deleted successfully!\n";
    return true;
}

PasswordEntry* PasswordManager::get_password(const std::string& service, const std::string& username) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return nullptr;
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return nullptr;
    }

    return &(it->second);
}

std::vector<PasswordEntry> PasswordManager::search_passwords(const std::string& search_term) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    return search_passwords_advanced(search_term);
}

std::vector<PasswordEntry> PasswordManager::search_passwords_advanced(const std::string& search_term, const std::string& category) {
    std::vector<PasswordEntry> results;
    std::string lower_search = search_term;
    std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);

    for (const auto& pair : passwords) {
        const PasswordEntry& entry = pair.second;

        // Skip if category filter is specified and doesn't match
        if (!category.empty() && entry.category != category) {
            continue;
        }

        std::string lower_service = entry.service;
        std::string lower_username = entry.username;
        std::string lower_notes = entry.notes;
        std::transform(lower_service.begin(), lower_service.end(), lower_service.begin(), ::tolower);
        std::transform(lower_username.begin(), lower_username.end(), lower_username.begin(), ::tolower);
        std::transform(lower_notes.begin(), lower_notes.end(), lower_notes.begin(), ::tolower);

        if (lower_service.find(lower_search) != std::string::npos ||
            lower_username.find(lower_search) != std::string::npos ||
            lower_notes.find(lower_search) != std::string::npos) {
            results.push_back(entry);
        }
    }

    return results;
}

std::vector<PasswordEntry> PasswordManager::get_all_passwords() {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    std::vector<PasswordEntry> all_passwords;
    for (const auto& pair : passwords) {
        all_passwords.push_back(pair.second);
    }
    return all_passwords;
}

std::vector<PasswordEntry> PasswordManager::search_passwords_by_category(const std::string& category) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    std::vector<PasswordEntry> results;
    for (const auto& pair : passwords) {
        if (pair.second.category == category) {
            results.push_back(pair.second);
        }
    }
    return results;
}

std::vector<std::string> PasswordManager::get_all_categories() {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    return std::vector<std::string>(categories.begin(), categories.end());
}

std::vector<PasswordEntry> PasswordManager::get_favorite_passwords() {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    std::vector<PasswordEntry> favorites;
    for (const auto& pair : passwords) {
        if (pair.second.is_favorite) {
            favorites.push_back(pair.second);
        }
    }
    return favorites;
}

bool PasswordManager::toggle_favorite(const std::string& service, const std::string& username) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return false;
    }

    it->second.is_favorite = !it->second.is_favorite;
    save_passwords_to_file();
    return true;
}

std::vector<PasswordEntry> PasswordManager::get_expired_passwords_public() {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    return get_expired_passwords();
}

std::vector<PasswordEntry> PasswordManager::get_expiring_soon_passwords_public(int days) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    return get_expiring_soon_passwords(days);
}

bool PasswordManager::update_password_expiry(const std::string& service, const std::string& username,
                                            const std::string& new_expiry_date) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return false;
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return false;
    }

    it->second.expiry_date = new_expiry_date;
    it->second.modified_date = Utils::get_current_timestamp();
    save_passwords_to_file();
    return true;
}

std::vector<std::string> PasswordManager::get_password_history(const std::string& service, const std::string& username) {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    std::string key = service + ":" + username;
    auto it = passwords.find(key);
    if (it == passwords.end()) {
        std::cout << "Password not found.\n";
        return {};
    }

    return it->second.password_history;
}

std::vector<std::pair<std::string, std::string>> PasswordManager::find_duplicate_passwords() {
    if (!is_authenticated) {
        std::cout << "Please login first.\n";
        return {};
    }

    std::map<std::string, std::vector<std::string>> password_groups;
    std::vector<std::pair<std::string, std::string>> duplicates;

    // Group passwords by their value
    for (const auto& pair : passwords) {
        password_groups[pair.second.password].push_back(pair.second.service + ":" + pair.second.username);
    }

    // Find groups with more than one password
    for (const auto& group : password_groups) {
        if (group.second.size() > 1) {
            for (size_t i = 0; i < group.second.size() - 1; ++i) {
                for (size_t j = i + 1; j < group.second.size(); ++j) {
                    duplicates.push_back(std::make_pair(group.second[i], group.second[j]));
                }
            }
        }
    }

    return duplicates;
}

void PasswordManager::add_to_password_history(const std::string& key, const std::string& old_password) {
    auto it = passwords.find(key);
    if (it != passwords.end()) {
        it->second.password_history.push_back(old_password);
        // Keep only last 10 passwords in history
        if (it->second.password_history.size() > 10) {
            it->second.password_history.erase(it->second.password_history.begin());
        }
    }
}

bool PasswordManager::is_password_expired(const std::string& expiry_date) {
    if (expiry_date.empty()) return false;

    // Simple date comparison (in real implementation, use proper date parsing)
    return expiry_date < Utils::get_current_timestamp().substr(0, 10);
}

std::vector<PasswordEntry> PasswordManager::get_expired_passwords() {
    std::vector<PasswordEntry> expired;
    for (const auto& pair : passwords) {
        if (is_password_expired(pair.second.expiry_date)) {
            expired.push_back(pair.second);
        }
    }
    return expired;
}

std::vector<PasswordEntry> PasswordManager::get_expiring_soon_passwords(int days) {
    std::vector<PasswordEntry> expiring_soon;
    std::string current_date = Utils::get_current_timestamp().substr(0, 10);

    for (const auto& pair : passwords) {
        if (!pair.second.expiry_date.empty() && !is_password_expired(pair.second.expiry_date)) {
            // Simple date comparison (in real implementation, use proper date arithmetic)
            if (pair.second.expiry_date <= current_date) {
                expiring_soon.push_back(pair.second);
            }
        }
    }
    return expiring_soon;
}

void PasswordManager::save_passwords_to_file() {
    std::ofstream file(data_file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for writing");
    }

    // Write master password hash
    file << master_password_hash << "\n";

    // Write password count
    file << passwords.size() << "\n";

    // Write each password entry (encrypted)
    for (const auto& pair : passwords) {
        const PasswordEntry& entry = pair.second;
        file << SimpleEncryption::encrypt_string(entry.service, master_password_hash) << "\n";
        file << SimpleEncryption::encrypt_string(entry.username, master_password_hash) << "\n";
        file << SimpleEncryption::encrypt_string(entry.password, master_password_hash) << "\n";
        file << SimpleEncryption::encrypt_string(entry.notes, master_password_hash) << "\n";
        file << SimpleEncryption::encrypt_string(entry.category, master_password_hash) << "\n";
        file << SimpleEncryption::encrypt_string(entry.expiry_date, master_password_hash) << "\n";
        file << (entry.is_favorite ? "1" : "0") << "\n";
        file << entry.created_date << "\n";
        file << entry.modified_date << "\n";

        // Write password history
        file << entry.password_history.size() << "\n";
        for (const auto& hist_pwd : entry.password_history) {
            file << SimpleEncryption::encrypt_string(hist_pwd, master_password_hash) << "\n";
        }
    }

    file.close();
}

void PasswordManager::load_passwords_from_file() {
    std::ifstream file(data_file_path);
    if (!file.is_open()) {
        return; // File doesn't exist yet
    }

    std::string line;

    // Read master password hash
    if (std::getline(file, line)) {
        master_password_hash = line;
    }

    // Read password count
    int count = 0;
    if (std::getline(file, line)) {
        count = std::stoi(line);
    }

    // Read each password entry
    for (int i = 0; i < count; ++i) {
        PasswordEntry entry;

        if (std::getline(file, line)) entry.service = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.username = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.password = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.notes = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.category = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.expiry_date = SimpleEncryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.is_favorite = (line == "1");
        if (std::getline(file, line)) entry.created_date = line;
        if (std::getline(file, line)) entry.modified_date = line;

        // Read password history
        int history_count = 0;
        if (std::getline(file, line)) history_count = std::stoi(line);
        for (int j = 0; j < history_count; ++j) {
            if (std::getline(file, line)) {
                entry.password_history.push_back(SimpleEncryption::decrypt_string(line, master_password_hash));
            }
        }

        std::string key = entry.service + ":" + entry.username;
        passwords[key] = entry;
        if (!entry.category.empty()) {
            categories.insert(entry.category);
        }
    }

    file.close();
}

std::string PasswordManager::hash_password(const std::string& password) {
    return SimpleEncryption::hash_password(password);
}

bool PasswordManager::verify_password_hash(const std::string& password, const std::string& hash) {
    return SimpleEncryption::hash_password(password) == hash;
}
