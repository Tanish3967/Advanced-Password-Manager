# Password Manager (CLI-based)

A secure, command-line password manager built in C++ with AES-256 encryption using OpenSSL.

## Features

### 🔐 Core Security Features
- **AES-256-CBC Encryption**: All passwords are encrypted using industry-standard AES-256 encryption
- **Master Password Protection**: Single master password protects all stored credentials
- **PBKDF2 Key Derivation**: Secure key derivation with 10,000 iterations
- **Salt Generation**: Random salt for each encryption operation

### 📝 Password Management
- **Store Passwords**: Add passwords with service name, username, and optional notes
- **Retrieve Passwords**: Securely retrieve stored passwords
- **Update Passwords**: Modify existing password entries
- **Delete Passwords**: Remove password entries with confirmation
- **Search Functionality**: Search passwords by service or username
- **List All Passwords**: View all stored password entries

### 🛡️ Security Tools
- **Password Strength Checker**: Analyze password strength with detailed feedback
- **Strong Password Generator**: Generate cryptographically secure passwords
- **Hidden Input**: Password input is hidden during typing

### 🔧 Technical Features
- **File I/O**: Encrypted storage in local file
- **STL Containers**: Uses hash maps and vectors for efficient data management
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Error Handling**: Comprehensive error handling and validation

## Prerequisites

### Required Dependencies
- **C++17 compatible compiler** (GCC 7+, Clang 5+, MSVC 2017+)
- **CMake 3.10+**
- **OpenSSL 1.1.0+**

### Installing Dependencies

#### Windows
```bash
# Install OpenSSL (using vcpkg)
vcpkg install openssl

# Or download from https://slproweb.com/products/Win32OpenSSL.html
```

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev
```

#### macOS
```bash
# Using Homebrew
brew install cmake openssl
```

## Building the Project

1. **Clone or download the project**
2. **Create build directory**:
   ```bash
   mkdir build
   cd build
   ```

3. **Configure with CMake**:
   ```bash
   cmake ..
   ```

4. **Build the project**:
   ```bash
   cmake --build .
   ```

5. **Run the password manager**:
   ```bash
   ./pwd_manager  # Linux/macOS
   pwd_manager.exe  # Windows
   ```

## Usage Guide

### First Time Setup
When you run the password manager for the first time, you'll be prompted to create a master password:
```
Welcome to Password Manager!
This is your first time setup. Please create a master password.
Enter master password: ********
Confirm master password: ********
Master password created successfully!
```

### Main Menu
The password manager provides a comprehensive menu system:
```
=== Password Manager ===
1. Add Password
2. Get Password
3. Update Password
4. Delete Password
5. Search Passwords
6. List All Passwords
7. Check Password Strength
8. Generate Strong Password
9. Change Master Password
10. Logout
0. Exit
```

### Common Operations

#### Adding a Password
1. Select option `1` from the main menu
2. Enter the service name (e.g., "Gmail", "GitHub")
3. Enter the username/email
4. Enter the password (input will be hidden)
5. Optionally add notes

#### Retrieving a Password
1. Select option `2` from the main menu
2. Enter the service name
3. Enter the username
4. View the complete password details

#### Checking Password Strength
1. Select option `7` from the main menu
2. Enter the password to analyze
3. Review the strength score and feedback

#### Generating a Strong Password
1. Select option `8` from the main menu
2. Enter desired length (default: 16 characters)
3. Copy the generated password

## Security Features

### Encryption Details
- **Algorithm**: AES-256-CBC
- **Key Derivation**: PBKDF2 with SHA-256
- **Iterations**: 10,000
- **Salt Size**: 32 bytes
- **IV Size**: 16 bytes

### Data Storage
- Passwords are stored in an encrypted file (`passwords.dat`)
- Each password entry is individually encrypted
- Master password hash is stored separately
- File format is not human-readable

### Security Best Practices
- Master password is never stored in plain text
- All sensitive data is encrypted before storage
- Random salt and IV for each encryption operation
- Secure memory handling (passwords cleared after use)

## File Structure

```
pswrd_mang/
├── include/
│   ├── password_manager.h      # Main password manager class
│   ├── encryption.h           # AES encryption utilities
│   ├── password_strength.h    # Password strength checker
│   └── utils.h               # Utility functions
├── src/
│   ├── main.cpp              # CLI interface and main application
│   ├── password_manager.cpp  # Password manager implementation
│   ├── encryption.cpp        # Encryption implementation
│   ├── password_strength.cpp # Strength checker implementation
│   └── utils.cpp            # Utility functions implementation
├── CMakeLists.txt           # Build configuration
├── README.md               # This file
└── passwords.dat           # Encrypted password storage (created after first use)
```

## Password Strength Analysis

The password strength checker evaluates passwords based on:
- **Length**: Longer passwords get higher scores
- **Character Variety**: Mix of lowercase, uppercase, digits, symbols
- **Pattern Detection**: Penalties for consecutive or repeated characters
- **Minimum Requirements**: 8+ characters recommended

Strength levels:
- **Very Weak** (0-19): Use at least 8 characters with mixed case, numbers, and symbols
- **Weak** (20-39): Add more variety and length
- **Medium** (40-59): Consider adding special characters and increasing length
- **Strong** (60-79): Good job!
- **Very Strong** (80-100): Excellent security!

## Troubleshooting

### Common Issues

#### Build Errors
- **OpenSSL not found**: Ensure OpenSSL is installed and CMake can find it
- **Compiler errors**: Make sure you have a C++17 compatible compiler
- **Linker errors**: Check that OpenSSL libraries are properly linked

#### Runtime Errors
- **File permission errors**: Ensure write permissions in the application directory
- **Memory errors**: Check available system memory
- **Encryption errors**: Verify OpenSSL installation

### Getting Help
If you encounter issues:
1. Check that all dependencies are properly installed
2. Verify your compiler supports C++17
3. Ensure OpenSSL is correctly linked
4. Check file permissions in the application directory

## Contributing

This is a learning project demonstrating:
- C++17 features and STL usage
- Cryptographic programming with OpenSSL
- File I/O and data persistence
- CLI application design
- Security best practices

Feel free to extend the functionality or improve the security features!

## License

This project is for educational purposes. Use at your own risk and ensure you understand the security implications of storing sensitive data.

## Disclaimer

This password manager is designed for educational purposes. For production use, consider established password managers like KeePass, Bitwarden, or 1Password that have undergone extensive security audits.
