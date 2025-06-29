#include "../include/password_recovery.h"
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <ctime>

// Password Recovery Implementation

std::vector<std::string> PasswordRecovery::generate_recovery_codes(int count, int length) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);
    std::vector<std::string> codes;
    std::set<std::string> used_codes;
    while (codes.size() < static_cast<size_t>(count)) {
        std::string code;
        for (int i = 0; i < length; ++i) {
            code += chars[dis(gen)];
        }
        if (used_codes.find(code) == used_codes.end()) {
            codes.push_back(code);
            used_codes.insert(code);
        }
    }
    return codes;
}

bool PasswordRecovery::validate_recovery_code(const std::string& code, const std::vector<std::string>& codes) {
    return std::find(codes.begin(), codes.end(), code) != codes.end();
}

void PasswordRecovery::set_security_question(const std::string& question, const std::string& answer_hash) {
    security_question = question;
    security_answer_hash = answer_hash;
}

std::string PasswordRecovery::get_security_question() const {
    return security_question;
}

bool PasswordRecovery::validate_security_answer(const std::string& answer_hash) const {
    return answer_hash == security_answer_hash;
}
