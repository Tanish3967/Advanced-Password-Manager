#include "../include/password_strength.h"
#include "../include/utils.h"
#include <cctype>
#include <algorithm>
#include <unordered_set>

PasswordStrengthResult PasswordStrengthChecker::check_strength(const std::string& password) {
    int score = calculate_score(password);
    std::string feedback = get_feedback(score);

    PasswordStrength strength;
    if (score < 20) strength = PasswordStrength::VERY_WEAK;
    else if (score < 40) strength = PasswordStrength::WEAK;
    else if (score < 60) strength = PasswordStrength::MEDIUM;
    else if (score < 80) strength = PasswordStrength::STRONG;
    else strength = PasswordStrength::VERY_STRONG;

    return {strength, score, feedback};
}

int PasswordStrengthChecker::calculate_score(const std::string& password) {
    int score = 0;

    // Length bonus
    if (password.length() >= 8) score += 10;
    if (password.length() >= 12) score += 10;
    if (password.length() >= 16) score += 10;

    // Character variety bonuses
    bool has_lower = false, has_upper = false, has_digit = false, has_special = false;

    for (char c : password) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }

    if (has_lower) score += 5;
    if (has_upper) score += 5;
    if (has_digit) score += 5;
    if (has_special) score += 10;

    // Penalties for common patterns
    if (password.length() < 8) score -= 10;

    // Check for consecutive characters
    for (size_t i = 1; i < password.length(); ++i) {
        if (password[i] == password[i-1] + 1 || password[i] == password[i-1] - 1) {
            score -= 2;
        }
    }

    // Check for repeated characters
    for (size_t i = 1; i < password.length(); ++i) {
        if (password[i] == password[i-1]) {
            score -= 3;
        }
    }

    return std::max(0, score);
}

std::string PasswordStrengthChecker::get_feedback(int score) {
    if (score < 20) {
        return "Very weak password. Use at least 8 characters with mixed case, numbers, and symbols.";
    } else if (score < 40) {
        return "Weak password. Add more variety and length.";
    } else if (score < 60) {
        return "Medium strength password. Consider adding special characters and increasing length.";
    } else if (score < 80) {
        return "Strong password. Good job!";
    } else {
        return "Very strong password. Excellent security!";
    }
}

std::string PasswordStrengthChecker::generate_strong_password(size_t length) {
    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    std::string password;
    password.reserve(length);

    // Ensure at least one character from each category
    password += lowercase[rand() % lowercase.length()];
    password += uppercase[rand() % uppercase.length()];
    password += digits[rand() % digits.length()];
    password += symbols[rand() % symbols.length()];

    // Fill the rest with random characters
    const std::string all_chars = lowercase + uppercase + digits + symbols;
    for (size_t i = 4; i < length; ++i) {
        password += all_chars[rand() % all_chars.length()];
    }

    // Shuffle the password
    std::random_shuffle(password.begin(), password.end());

    return password;
}

// Password Strength Visualization

std::string PasswordStrengthVisualizer::get_strength_bar(int score) {
    std::string bar = "[";
    int filled = score / 10; // Convert 0-100 to 0-10 bars

    for (int i = 0; i < 10; ++i) {
        if (i < filled) {
            bar += "█";
        } else {
            bar += "░";
        }
    }
    bar += "]";
    return bar;
}

std::string PasswordStrengthVisualizer::get_strength_color(int score) {
    if (score >= 80) return "🟢"; // Green
    if (score >= 60) return "🟡"; // Yellow
    if (score >= 40) return "🟠"; // Orange
    return "🔴"; // Red
}

std::string PasswordStrengthVisualizer::get_strength_text(int score) {
    if (score >= 80) return "Very Strong";
    if (score >= 60) return "Strong";
    if (score >= 40) return "Moderate";
    if (score >= 20) return "Weak";
    return "Very Weak";
}

std::string PasswordStrengthVisualizer::visualize_strength(const std::string& password) {
    int score = calculate_strength(password);

    std::string result = "\n🔐 Password Strength Analysis:\n";
    result += "==============================\n";
    result += "Password: " + std::string(password.length(), '*') + "\n";
    result += "Length: " + std::to_string(password.length()) + " characters\n";
    result += "Score: " + std::to_string(score) + "/100\n";
    result += "Strength: " + get_strength_color(score) + " " + get_strength_text(score) + "\n";
    result += "Visual: " + get_strength_bar(score) + "\n";

    // Add detailed analysis
    result += "\n📊 Detailed Analysis:\n";
    result += "Uppercase letters: " + std::to_string(count_uppercase(password)) + "\n";
    result += "Lowercase letters: " + std::to_string(count_lowercase(password)) + "\n";
    result += "Numbers: " + std::to_string(count_numbers(password)) + "\n";
    result += "Special chars: " + std::to_string(count_special(password)) + "\n";
    result += "Unique chars: " + std::to_string(count_unique(password)) + "\n";

    // Add suggestions
    result += "\n💡 Suggestions:\n";
    if (password.length() < 8) {
        result += "• Make password at least 8 characters long\n";
    }
    if (count_uppercase(password) == 0) {
        result += "• Add uppercase letters (A-Z)\n";
    }
    if (count_lowercase(password) == 0) {
        result += "• Add lowercase letters (a-z)\n";
    }
    if (count_numbers(password) == 0) {
        result += "• Add numbers (0-9)\n";
    }
    if (count_special(password) == 0) {
        result += "• Add special characters (!@#$%^&*)\n";
    }
    if (count_unique(password) < password.length() * 0.7) {
        result += "• Use more unique characters\n";
    }

    return result;
}

int PasswordStrengthVisualizer::count_uppercase(const std::string& password) {
    int count = 0;
    for (char c : password) {
        if (isupper(c)) count++;
    }
    return count;
}

int PasswordStrengthVisualizer::count_lowercase(const std::string& password) {
    int count = 0;
    for (char c : password) {
        if (islower(c)) count++;
    }
    return count;
}

int PasswordStrengthVisualizer::count_numbers(const std::string& password) {
    int count = 0;
    for (char c : password) {
        if (isdigit(c)) count++;
    }
    return count;
}

int PasswordStrengthVisualizer::count_special(const std::string& password) {
    int count = 0;
    for (char c : password) {
        if (!isalnum(c)) count++;
    }
    return count;
}

int PasswordStrengthVisualizer::count_unique(const std::string& password) {
    std::set<char> unique_chars(password.begin(), password.end());
    return unique_chars.size();
}
