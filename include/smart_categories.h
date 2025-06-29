#ifndef SMART_CATEGORIES_H
#define SMART_CATEGORIES_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>

struct Category {
    std::string name;
    std::string color;           // Hex color code
    std::string description;
    std::string parent;          // For nested categories
    std::vector<std::string> tags;
    bool is_system;              // System-generated vs user-created
    int priority;                // For sorting
};

struct Tag {
    std::string name;
    std::string color;
    std::string description;
    int usage_count;
};

class SmartCategories {
public:
    // Category management
    static std::vector<Category> get_all_categories();
    static Category create_category(const std::string& name, const std::string& color = "#007ACC",
                                   const std::string& description = "", const std::string& parent = "");
    static bool update_category(const std::string& name, const Category& new_data);
    static bool delete_category(const std::string& name);

    // Auto-categorization
    static std::string auto_categorize_service(const std::string& service);
    static std::vector<std::string> suggest_tags(const std::string& service, const std::string& username);
    static std::string suggest_color(const std::string& category);

    // Tag management
    static std::vector<Tag> get_all_tags();
    static Tag create_tag(const std::string& name, const std::string& color = "#666666");
    static bool update_tag(const std::string& name, const Tag& new_data);
    static bool delete_tag(const std::string& name);

    // Smart features
    static std::vector<std::string> find_similar_services(const std::string& service);
    static std::vector<std::string> get_related_categories(const std::string& category);
    static std::map<std::string, int> get_category_usage_stats();
    static std::vector<std::string> get_popular_tags(int limit = 10);

    // Search and filtering
    static std::vector<std::string> search_categories(const std::string& query);
    static std::vector<std::string> search_tags(const std::string& query);
    static std::vector<std::string> filter_by_category(const std::string& category);
    static std::vector<std::string> filter_by_tags(const std::vector<std::string>& tags);

    // Color utilities
    static std::vector<std::string> get_predefined_colors();
    static std::string get_contrasting_color(const std::string& background_color);
    static bool is_valid_color(const std::string& color);

    // Import/Export
    static bool export_categories(const std::string& filename);
    static bool import_categories(const std::string& filename);

private:
    // Predefined categories and their patterns
    static std::map<std::string, std::vector<std::string>> get_service_patterns();
    static std::map<std::string, std::string> get_category_colors();
    static std::vector<std::string> get_system_categories();

    // Pattern matching
    static bool matches_pattern(const std::string& text, const std::string& pattern);
    static double calculate_similarity(const std::string& str1, const std::string& str2);
};

#endif // SMART_CATEGORIES_H
