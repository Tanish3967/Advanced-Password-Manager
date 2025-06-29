#ifndef PASSWORD_RECOVERY_H
#define PASSWORD_RECOVERY_H

#include <string>
#include <vector>
#include <map>
#include <ctime>

struct SecurityQuestion {
    std::string question;
    std::string answer_hash;     // Hashed answer for security
    bool is_required;
    int question_id;
};

struct RecoveryMethod {
    std::string method_type;     // "email", "phone", "backup_codes", "trusted_contact"
    std::string identifier;      // email address, phone number, etc.
    bool is_verified;
    bool is_enabled;
    std::time_t last_used;
};

struct RecoverySession {
    std::string session_id;
    std::string user_identifier;
    std::time_t created_time;
    std::time_t expires_time;
    std::vector<std::string> completed_steps;
    bool is_completed;
    std::string recovery_method_used;
};

class PasswordRecovery {
public:
    // Recovery setup
    static bool setup_recovery_method(const std::string& method_type, const std::string& identifier);
    static bool verify_recovery_method(const std::string& method_type, const std::string& identifier,
                                      const std::string& verification_code);
    static bool remove_recovery_method(const std::string& method_type, const std::string& identifier);
    static std::vector<RecoveryMethod> get_recovery_methods();

    // Security questions
    static bool set_security_questions(const std::vector<SecurityQuestion>& questions);
    static bool add_security_question(const std::string& question, const std::string& answer, bool required = true);
    static bool update_security_question(int question_id, const std::string& question, const std::string& answer);
    static bool remove_security_question(int question_id);
    static std::vector<SecurityQuestion> get_security_questions();
    static bool validate_security_answers(const std::map<int, std::string>& answers);

    // Recovery process
    static std::string initiate_recovery(const std::string& user_identifier);
    static bool validate_recovery_session(const std::string& session_id);
    static bool complete_recovery_step(const std::string& session_id, const std::string& step,
                                      const std::string& verification_data);
    static bool finalize_recovery(const std::string& session_id, const std::string& new_master_password);
    static bool cancel_recovery(const std::string& session_id);

    // Email recovery
    static bool send_recovery_email(const std::string& email_address);
    static bool validate_recovery_email_code(const std::string& email, const std::string& code);
    static bool resend_recovery_email(const std::string& email_address);

    // Phone recovery (SMS)
    static bool send_recovery_sms(const std::string& phone_number);
    static bool validate_recovery_sms_code(const std::string& phone, const std::string& code);

    // Backup codes
    static std::vector<std::string> generate_backup_codes(int count = 10, int length = 8);
    static bool validate_backup_code(const std::string& code);
    static bool regenerate_backup_codes();
    static std::vector<std::string> get_remaining_backup_codes();

    // Trusted contacts
    static bool add_trusted_contact(const std::string& name, const std::string& email,
                                   const std::string& relationship);
    static bool remove_trusted_contact(const std::string& email);
    static bool request_trusted_contact_approval(const std::string& contact_email);
    static bool validate_trusted_contact_approval(const std::string& contact_email, const std::string& approval_code);
    static std::vector<std::map<std::string, std::string>> get_trusted_contacts();

    // Account restoration
    static bool restore_account_from_backup(const std::string& backup_file, const std::string& backup_password);
    static bool export_account_for_recovery(const std::string& filename, const std::string& encryption_password);
    static bool import_account_from_recovery(const std::string& filename, const std::string& encryption_password);

    // Recovery history and monitoring
    static std::vector<RecoverySession> get_recovery_history();
    static bool log_recovery_attempt(const std::string& user_identifier, const std::string& method_used,
                                    bool success, const std::string& details = "");
    static std::map<std::string, int> get_recovery_attempt_stats();
    static bool detect_suspicious_recovery_activity();

    // Security features
    static bool set_recovery_cooldown(int minutes);
    static bool set_max_recovery_attempts(int attempts);
    static bool lock_recovery_for_user(const std::string& user_identifier, int minutes);
    static bool unlock_recovery_for_user(const std::string& user_identifier);

    // Configuration
    static bool load_recovery_config(const std::string& config_file);
    static bool save_recovery_config(const std::string& config_file);
    static bool reset_recovery_settings();

    // Utility functions
    static std::string generate_recovery_code(int length = 6);
    static std::string hash_answer(const std::string& answer);
    static bool verify_answer_hash(const std::string& answer, const std::string& hash);
    static std::time_t get_recovery_session_expiry();
    static bool is_recovery_session_expired(const RecoverySession& session);

private:
    static const int DEFAULT_RECOVERY_CODE_LENGTH = 6;
    static const int DEFAULT_BACKUP_CODE_LENGTH = 8;
    static const int DEFAULT_RECOVERY_COOLDOWN = 15; // minutes
    static const int DEFAULT_MAX_ATTEMPTS = 3;
    static const int DEFAULT_SESSION_TIMEOUT = 30; // minutes

    // Internal state
    static std::vector<RecoveryMethod> recovery_methods;
    static std::vector<SecurityQuestion> security_questions;
    static std::vector<std::string> backup_codes;
    static std::vector<RecoverySession> active_sessions;
    static std::map<std::string, int> recovery_attempts;

    // Helper functions
    static std::string generate_session_id();
    static bool send_email(const std::string& to, const std::string& subject, const std::string& body);
    static bool send_sms(const std::string& to, const std::string& message);
    static std::string generate_verification_code();
    static bool validate_verification_code(const std::string& stored_code, const std::string& provided_code);
};

#endif // PASSWORD_RECOVERY_H
