#pragma once

#include <string>

enum class PasswordStrength {
    VERY_WEAK,
    WEAK,
    MEDIUM,
    STRONG,
    VERY_STRONG
};

struct PasswordStrengthResult {
    PasswordStrength strength;
    int score;
    std::string feedback;
};

class PasswordStrengthChecker {
public:
    static PasswordStrengthResult check_strength(const std::string& password);
    static std::string generate_strong_password(size_t length = 16);

private:
    static int calculate_score(const std::string& password);
    static std::string get_feedback(int score);
};
