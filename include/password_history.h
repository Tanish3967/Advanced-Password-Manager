#ifndef PASSWORD_HISTORY_H
#define PASSWORD_HISTORY_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <ctime>

struct PasswordVersion {
    std::string password;
    std::string notes;
    std::string category;
    std::string expiry_date;
    std::string modified_by;     // User who made the change
    std::string change_reason;   // Why the password was changed
    std::time_t timestamp;
    int version_number;
    bool is_current;             // Is this the current version
};

struct PasswordAudit {
    std::string service;
    std::string username;
    std::string action;          // "created", "updated", "deleted", "viewed", "shared"
    std::string details;
    std::string user_ip;         // IP address of the user
    std::time_t timestamp;
    std::string session_id;
};

class PasswordHistory {
public:
    // Version management
    static std::vector<PasswordVersion> get_password_history(const std::string& service, const std::string& username);
    static bool add_version(const std::string& service, const std::string& username,
                           const std::string& password, const std::string& notes = "",
                           const std::string& category = "", const std::string& expiry_date = "",
                           const std::string& change_reason = "");
    static bool rollback_to_version(const std::string& service, const std::string& username, int version_number);
    static PasswordVersion get_version(const std::string& service, const std::string& username, int version_number);

    // History limits and cleanup
    static bool set_max_versions(const std::string& service, const std::string& username, int max_versions);
    static bool cleanup_old_versions(const std::string& service, const std::string& username, int keep_versions = 10);
    static bool cleanup_all_old_versions(int keep_versions = 10);

    // Audit trail
    static bool add_audit_entry(const std::string& service, const std::string& username,
                               const std::string& action, const std::string& details = "");
    static std::vector<PasswordAudit> get_audit_trail(const std::string& service = "",
                                                     const std::string& username = "",
                                                     std::time_t from_time = 0,
                                                     std::time_t to_time = 0);
    static std::vector<PasswordAudit> get_user_audit_trail(const std::string& user_ip,
                                                          std::time_t from_time = 0);

    // Analytics and reporting
    static std::map<std::string, int> get_password_change_frequency();
    static std::vector<std::string> get_passwords_changed_recently(int days = 30);
    static std::vector<std::string> get_passwords_not_changed_in(int days = 90);
    static std::map<std::string, std::vector<std::string>> get_change_patterns();

    // Export and backup
    static bool export_history(const std::string& filename, const std::string& service = "",
                              const std::string& username = "");
    static bool export_audit_trail(const std::string& filename, std::time_t from_time = 0);
    static bool backup_history_data(const std::string& backup_dir);

    // Security features
    static bool encrypt_history_data(const std::string& encryption_key);
    static bool decrypt_history_data(const std::string& encryption_key);
    static bool set_history_retention_policy(int days_to_keep);

    // Utility functions
    static std::string format_timestamp(std::time_t timestamp);
    static std::time_t parse_timestamp(const std::string& timestamp_str);
    static std::string get_time_ago(std::time_t timestamp);
    static bool is_version_expired(const PasswordVersion& version);

private:
    static const int DEFAULT_MAX_VERSIONS = 20;
    static const int DEFAULT_RETENTION_DAYS = 365;

    // Helper functions
    static std::string generate_session_id();
    static std::string get_user_ip();
    static bool validate_version_data(const PasswordVersion& version);
    static std::vector<std::string> get_change_reasons();
};

#endif // PASSWORD_HISTORY_H
