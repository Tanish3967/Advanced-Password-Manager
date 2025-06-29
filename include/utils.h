#pragma once

#include <string>
#include <vector>

namespace Utils {
    // Convert string to hex
    std::string bytes_to_hex(const std::vector<unsigned char>& bytes);

    // Convert hex string to bytes
    std::vector<unsigned char> hex_to_bytes(const std::string& hex);

    // Base64 encode
    std::string base64_encode(const std::vector<unsigned char>& data);

    // Base64 decode
    std::vector<unsigned char> base64_decode(const std::string& encoded);

    // Get current timestamp
    std::string get_current_timestamp();

    // Hide password input (cross-platform)
    std::string get_hidden_input(const std::string& prompt);

    // Clear screen
    void clear_screen();

    // Generate random string
    std::string generate_random_string(size_t length);
}
