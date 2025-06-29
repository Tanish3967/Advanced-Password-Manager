#include "../include/password_manager.h"
#include "../include/encryption.h"
#include "../include/utils.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

PasswordManager::PasswordManager(const std::string& file_path)
    : data_file_path(file_path), is_authenticated(false) {
}

bool PasswordManager::initialize() {
    // Check if data file exists
    std::ifstream file(data_file_path);
    if (!file.good()) {
        // First time setup - create master password
        std::cout << "Welcome to Password Manager!\n";
        std::cout << "This is your first time setup. Please create a master password.\n";

        std::string master_pwd = Utils::get_hidden_input("Enter master password: ");
        std::string confirm_pwd = Utils::get_hidden_input("Confirm master password: ");

        if (master_pwd != confirm_pwd) {
            std::cout << "Passwords don't match!\n";
            return false;
        }

        master_password_hash = hash_password(master_pwd);
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

    if (verify_password_hash(master_password, master_password_hash)) {
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

    if (!verify_password_hash(old_password, master_password_hash)) {
        std::cout << "Incorrect old password.\n";
        return false;
    }

    master_password_hash = hash_password(new_password);
    save_passwords_to_file();
    std::cout << "Master password changed successfully!\n";
    return true;
}

bool PasswordManager::add_password(const std::string& service, const std::string& username,
                                 const std::string& password, const std::string& notes) {
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
    entry.created_date = Utils::get_current_timestamp();
    entry.modified_date = entry.created_date;

    passwords[key] = entry;
    save_passwords_to_file();
    std::cout << "Password added successfully!\n";
    return true;
}

bool PasswordManager::update_password(const std::string& service, const std::string& username,
                                    const std::string& new_password, const std::string& notes) {
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

    it->second.password = new_password;
    if (!notes.empty()) {
        it->second.notes = notes;
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

    std::vector<PasswordEntry> results;
    std::string lower_search = search_term;
    std::transform(lower_search.begin(), lower_search.end(), lower_search.begin(), ::tolower);

    for (const auto& pair : passwords) {
        std::string lower_service = pair.second.service;
        std::string lower_username = pair.second.username;
        std::transform(lower_service.begin(), lower_service.end(), lower_service.begin(), ::tolower);
        std::transform(lower_username.begin(), lower_username.end(), lower_username.begin(), ::tolower);

        if (lower_service.find(lower_search) != std::string::npos ||
            lower_username.find(lower_search) != std::string::npos) {
            results.push_back(pair.second);
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

void PasswordManager::save_passwords_to_file() {
    std::ofstream file(data_file_path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file for writing");
    }

    // Write master password hash
    file << master_password_hash << "\n";

    // Write password count
    file << passwords.size() << "\n";

    // Write each password entry
    for (const auto& pair : passwords) {
        const PasswordEntry& entry = pair.second;
        file << Encryption::encrypt_string(entry.service, master_password_hash) << "\n";
        file << Encryption::encrypt_string(entry.username, master_password_hash) << "\n";
        file << Encryption::encrypt_string(entry.password, master_password_hash) << "\n";
        file << Encryption::encrypt_string(entry.notes, master_password_hash) << "\n";
        file << entry.created_date << "\n";
        file << entry.modified_date << "\n";
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

        if (std::getline(file, line)) entry.service = Encryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.username = Encryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.password = Encryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.notes = Encryption::decrypt_string(line, master_password_hash);
        if (std::getline(file, line)) entry.created_date = line;
        if (std::getline(file, line)) entry.modified_date = line;

        std::string key = entry.service + ":" + entry.username;
        passwords[key] = entry;
    }

    file.close();
}

std::string PasswordManager::hash_password(const std::string& password) {
    // Simple SHA-256 hash for master password
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password.c_str(), password.length());
    SHA256_Final(hash, &sha256);

    return Utils::bytes_to_hex(std::vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH));
}

bool PasswordManager::verify_password_hash(const std::string& password, const std::string& hash) {
    std::string computed_hash = hash_password(password);
    return computed_hash == hash;
}
