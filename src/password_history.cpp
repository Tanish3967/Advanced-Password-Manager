#include "../include/password_history.h"
#include <unordered_map>
#include <vector>
#include <string>
#include <ctime>

// Password history management

void PasswordHistory::add_version(const std::string& password_id, const std::string& password) {
    time_t now = std::time(nullptr);
    history[password_id].push_back({password, now});
}

std::vector<PasswordHistory::Version> PasswordHistory::get_versions(const std::string& password_id) const {
    auto it = history.find(password_id);
    if (it != history.end()) {
        return it->second;
    }
    return {};
}

PasswordHistory::Version PasswordHistory::get_latest(const std::string& password_id) const {
    auto it = history.find(password_id);
    if (it != history.end() && !it->second.empty()) {
        return it->second.back();
    }
    return {"", 0};
}

bool PasswordHistory::restore_version(const std::string& password_id, size_t version_index) {
    auto it = history.find(password_id);
    if (it != history.end() && version_index < it->second.size()) {
        // Move the selected version to the end (latest)
        it->second.push_back(it->second[version_index]);
        return true;
    }
    return false;
}
