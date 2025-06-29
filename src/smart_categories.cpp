#include "../include/smart_categories.h"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <algorithm>

// Category and tag management for passwords

void SmartCategories::add_category(const std::string& category) {
    categories.insert(category);
}

void SmartCategories::remove_category(const std::string& category) {
    categories.erase(category);
    // Remove category from all passwords
    for (auto& entry : password_categories) {
        entry.second.erase(category);
    }
}

std::vector<std::string> SmartCategories::list_categories() const {
    return std::vector<std::string>(categories.begin(), categories.end());
}

void SmartCategories::assign_category(const std::string& password_id, const std::string& category) {
    categories.insert(category);
    password_categories[password_id].insert(category);
}

std::vector<std::string> SmartCategories::get_categories(const std::string& password_id) const {
    auto it = password_categories.find(password_id);
    if (it != password_categories.end()) {
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }
    return {};
}

void SmartCategories::add_tag(const std::string& tag) {
    tags.insert(tag);
}

void SmartCategories::remove_tag(const std::string& tag) {
    tags.erase(tag);
    for (auto& entry : password_tags) {
        entry.second.erase(tag);
    }
}

std::vector<std::string> SmartCategories::list_tags() const {
    return std::vector<std::string>(tags.begin(), tags.end());
}

void SmartCategories::assign_tag(const std::string& password_id, const std::string& tag) {
    tags.insert(tag);
    password_tags[password_id].insert(tag);
}

std::vector<std::string> SmartCategories::get_tags(const std::string& password_id) const {
    auto it = password_tags.find(password_id);
    if (it != password_tags.end()) {
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }
    return {};
}

std::vector<std::string> SmartCategories::search_by_category(const std::string& category) const {
    std::vector<std::string> result;
    for (const auto& entry : password_categories) {
        if (entry.second.count(category)) {
            result.push_back(entry.first);
        }
    }
    return result;
}

std::vector<std::string> SmartCategories::search_by_tag(const std::string& tag) const {
    std::vector<std::string> result;
    for (const auto& entry : password_tags) {
        if (entry.second.count(tag)) {
            result.push_back(entry.first);
        }
    }
    return result;
}
