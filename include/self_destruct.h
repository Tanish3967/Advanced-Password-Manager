#ifndef SELF_DESTRUCT_H
#define SELF_DESTRUCT_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <functional>

struct SecurityEvent {
    std::string event_type;      // "failed_login", "suspicious_activity", "remote_wipe", etc.
    std::string description;
    std::string user_ip;
    std::string user_agent;
    std::time_t timestamp;
    int severity;                // 1-10 scale
    bool handled;
};

struct SelfDestructRule {
    std::string rule_name;
    std::string trigger_condition;  // "failed_logins", "suspicious_activity", "time_limit", "remote_command"
    int threshold;                  // Number of events before triggering
    std::time_t time_window;        // Time window for counting events
    std::string action;             // "lock", "wipe", "delete", "shutdown"
    bool enabled;
    std::string description;
};

class SelfDestruct {
public:
    // Core self-destruct functionality
    static bool enable_self_destruct_mode();
    static bool disable_self_destruct_mode();
    static bool is_self_destruct_enabled();

    // Remote wipe capabilities
    static bool initiate_remote_wipe(const std::string& trigger_reason = "remote_command");
    static bool schedule_remote_wipe(std::time_t wipe_time, const std::string& reason = "scheduled");
    static bool cancel_scheduled_wipe();
    static bool is_wipe_scheduled();

    // Time-based deletion
    static bool set_auto_delete_timer(int days);
    static bool extend_auto_delete_timer(int additional_days);
    static int get_remaining_days();
    static bool cancel_auto_delete();

    // Suspicious activity detection
    static bool add_security_event(const std::string& event_type, const std::string& description,
                                  int severity = 5);
    static std::vector<SecurityEvent> get_recent_security_events(int hours = 24);
    static bool check_suspicious_activity();
    static bool reset_security_events();

    // Rule-based protection
    static bool add_security_rule(const SelfDestructRule& rule);
    static bool update_security_rule(const std::string& rule_name, const SelfDestructRule& new_rule);
    static bool delete_security_rule(const std::string& rule_name);
    static std::vector<SelfDestructRule> get_all_rules();
    static bool evaluate_security_rules();

    // Lockdown mode
    static bool enable_lockdown_mode();
    static bool disable_lockdown_mode();
    static bool is_lockdown_active();
    static bool set_lockdown_duration(int minutes);

    // Emergency features
    static bool emergency_wipe_all_data();
    static bool emergency_lock_system();
    static bool emergency_shutdown();
    static bool send_emergency_alert(const std::string& message);

    // Monitoring and alerts
    static bool set_alert_threshold(int failed_attempts);
    static bool add_alert_recipient(const std::string& email);
    static bool remove_alert_recipient(const std::string& email);
    static std::vector<std::string> get_alert_recipients();
    static bool send_security_alert(const std::string& event_type, const std::string& details);

    // Recovery and backup
    static bool create_emergency_backup(const std::string& backup_location);
    static bool restore_from_backup(const std::string& backup_location);
    static bool set_recovery_key(const std::string& recovery_key);
    static bool validate_recovery_key(const std::string& recovery_key);

    // Configuration
    static bool load_security_config(const std::string& config_file);
    static bool save_security_config(const std::string& config_file);
    static bool reset_to_default_config();

    // Utility functions
    static std::string get_system_status();
    static std::map<std::string, int> get_security_stats();
    static bool is_system_compromised();
    static std::string get_last_security_report();

private:
    static const int DEFAULT_FAILED_LOGIN_THRESHOLD = 5;
    static const int DEFAULT_SUSPICIOUS_ACTIVITY_THRESHOLD = 3;
    static const int DEFAULT_AUTO_DELETE_DAYS = 30;

    // Internal state
    static bool self_destruct_enabled;
    static bool lockdown_active;
    static std::time_t scheduled_wipe_time;
    static std::time_t auto_delete_time;
    static std::vector<SecurityEvent> security_events;
    static std::vector<SelfDestructRule> security_rules;
    static std::vector<std::string> alert_recipients;

    // Helper functions
    static bool wipe_password_data();
    static bool wipe_history_data();
    static bool wipe_audit_data();
    static bool lock_user_interface();
    static bool detect_brute_force_attack();
    static bool detect_anomalous_activity();
    static std::string generate_security_report();
};

#endif // SELF_DESTRUCT_H
