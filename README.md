# Advanced Password Manager (CLI-based)

A comprehensive, secure command-line password manager built in C++ with multiple encryption options, advanced features, and modern security practices.

## Features

### 🔐 Core Security Features
- **Multiple Encryption Options**:
  - AES-256-CBC Encryption (with OpenSSL)
  - XOR-based encryption (dependency-free)
  - PBKDF2 Key Derivation with salted hashing
- **Master Password Protection**: Single master password protects all stored credentials
- **Two-Factor Authentication (TOTP)**: Time-based one-time passwords for additional security
- **Self-Destruct Mode**: Emergency data deletion with configurable triggers

### 📝 Advanced Password Management
- **Store Passwords**: Add passwords with service name, username, and optional notes
- **Retrieve Passwords**: Securely retrieve stored passwords with username selection
- **Update Passwords**: Modify existing password entries
- **Delete Passwords**: Remove password entries with confirmation
- **Search & Filter**: Advanced search with multiple criteria
- **List All Passwords**: View all stored password entries
- **Password History**: Track password changes and versions
- **Smart Categories & Tags**: Organize passwords with custom categories and tags

### 🛡️ Security Tools
- **Password Strength Checker**: Analyze password strength with detailed feedback
- **Strong Password Generator**: Generate cryptographically secure passwords with custom rules
- **Password Strength Visualization**: Visual representation of password strength
- **Breach Monitoring**: Check if passwords have been compromised
- **Hidden Input**: Password input is hidden during typing

### 🔄 Data Management
- **Password Sharing**: Multiple sharing methods (text, file, link, email template)
- **QR Code Generation**: Generate QR codes for password sharing
- **Import/Export**: Backup and restore functionality
- **Mobile Companion**: Export data for mobile apps
- **Bulk Operations**: Manage multiple passwords efficiently

### 🔧 Technical Features
- **File I/O**: Encrypted storage in local file
- **STL Containers**: Uses hash maps and vectors for efficient data management
- **Cross-platform**: Works on Windows, Linux, and macOS
- **Error Handling**: Comprehensive error handling and validation
- **Offline Mode**: Works without internet connection
- **Emergency Access**: Grant temporary access to trusted contacts

## Prerequisites

### Required Dependencies
- **C++11 compatible compiler** (GCC 4.8+, Clang 3.3+, MSVC 2015+)
- **CMake 3.10+** (optional, for advanced builds)
- **OpenSSL 1.1.0+** (optional, for AES encryption)

### Installing Dependencies

#### Windows
```bash
# Install OpenSSL (using vcpkg) - Optional for AES encryption
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

### Quick Build (Recommended)
For a dependency-free version with XOR encryption:
```bash
# Windows
build_simple.bat

# Or manually
g++ -std=c++11 -o pwd_manager_simple.exe src/standalone_password_manager.cpp src/simple_encryption.cpp src/simple_utils.cpp src/password_strength.cpp src/qr_code.cpp src/password_sharing.cpp src/two_factor_auth.cpp src/password_history.cpp src/smart_categories.cpp src/self_destruct.cpp src/password_recovery.cpp src/advanced_features.cpp -I include/
```

### Advanced Build (with OpenSSL)
For AES-256 encryption:
```bash
# Windows
build_advanced.bat

# Or manually
g++ -std=c++11 -o pwd_manager_advanced.exe src/main.cpp src/password_manager.cpp src/encryption.cpp src/password_strength.cpp src/utils.cpp src/qr_code.cpp src/password_sharing.cpp src/two_factor_auth.cpp src/password_history.cpp src/smart_categories.cpp src/self_destruct.cpp src/password_recovery.cpp src/advanced_features.cpp src/advanced_encryption.cpp -I include/ -lssl -lcrypto
```

### CMake Build
```bash
mkdir build
cd build
cmake ..
cmake --build .
```

## Usage Guide

### First Time Setup
When you run the password manager for the first time, you'll be prompted to create a master password:
```
Welcome to Advanced Password Manager!
This is your first time setup. Please create a master password.
Enter master password: ********
Confirm master password: ********
Master password created successfully!
```

### Main Menu
The password manager provides a comprehensive menu system:
```
=== Advanced Password Manager ===
1. Add Password
2. Get Password
3. Update Password
4. Delete Password
5. Search Passwords
6. List All Passwords
7. Check Password Strength
8. Generate Strong Password
9. Password Sharing
10. QR Code Generation
11. Two-Factor Authentication
12. Password History
13. Smart Categories
14. Self-Destruct Mode
15. Password Recovery
16. Mobile Companion
17. Emergency Access
18. Settings & Help
19. Change Master Password
20. Logout
0. Exit
```

### Common Operations

#### Adding a Password
1. Select option `1` from the main menu
2. Enter the service name (e.g., "Gmail", "GitHub")
3. Enter the username/email
4. Enter the password (input will be hidden)
5. Optionally add notes, categories, and tags

#### Retrieving a Password
1. Select option `2` from the main menu
2. Enter the service name
3. Select from available usernames
4. View the complete password details

#### Password Sharing
1. Select option `9` from the main menu
2. Choose sharing method (text, file, link, email)
3. Select password to share
4. Set optional encryption and expiry
5. Share the generated data

#### Two-Factor Authentication
1. Select option `11` from the main menu
2. Generate TOTP secret for a service
3. Scan QR code with authenticator app
4. Verify setup with generated code

## Security Features

### Encryption Details
- **Algorithm**: AES-256-CBC (with OpenSSL) or XOR (dependency-free)
- **Key Derivation**: PBKDF2 with SHA-256 or salted hashing
- **Iterations**: 10,000 (AES) or configurable (XOR)
- **Salt Size**: 32 bytes (AES) or 16 bytes (XOR)
- **IV Size**: 16 bytes

### Data Storage
- Passwords are stored in an encrypted file (`passwords.dat`)
- Each password entry is individually encrypted
- Master password hash is stored with salt
- File format is not human-readable

### Security Best Practices
- Master password is never stored in plain text
- All sensitive data is encrypted before storage
- Random salt and IV for each encryption operation
- Secure memory handling (passwords cleared after use)
- TOTP for additional authentication layer
- Self-destruct capability for emergency situations

## File Structure

```
pswrd_mang/
├── include/
│   ├── password_manager.h          # Main password manager class
│   ├── encryption.h               # AES encryption utilities
│   ├── advanced_encryption.h      # Advanced encryption features
│   ├── simple_encryption.h        # XOR encryption utilities
│   ├── password_strength.h        # Password strength checker
│   ├── utils.h                   # Utility functions
│   ├── simple_utils.h            # Simple utility functions
│   ├── qr_code.h                 # QR code generation
│   ├── password_sharing.h        # Password sharing features
│   ├── two_factor_auth.h         # TOTP implementation
│   ├── password_history.h        # Password versioning
│   ├── smart_categories.h        # Categories and tags
│   ├── self_destruct.h           # Emergency deletion
│   ├── password_recovery.h       # Recovery mechanisms
│   ├── advanced_features.h       # Advanced features
│   └── qrcodegen.hpp             # QR code library
├── src/
│   ├── main.cpp                  # CLI interface (AES version)
│   ├── standalone_password_manager.cpp  # Main CLI (XOR version)
│   ├── main_simple.cpp           # Simple CLI interface
│   ├── password_manager.cpp      # Password manager implementation
│   ├── encryption.cpp            # AES encryption implementation
│   ├── advanced_encryption.cpp   # Advanced encryption
│   ├── simple_encryption.cpp     # XOR encryption implementation
│   ├── password_strength.cpp     # Strength checker implementation
│   ├── utils.cpp                 # Utility functions implementation
│   ├── simple_utils.cpp          # Simple utilities
│   ├── qr_code.cpp               # QR code implementation
│   ├── password_sharing.cpp      # Sharing implementation
│   ├── two_factor_auth.cpp       # TOTP implementation
│   ├── password_history.cpp      # History implementation
│   ├── smart_categories.cpp      # Categories implementation
│   ├── self_destruct.cpp         # Self-destruct implementation
│   ├── password_recovery.cpp     # Recovery implementation
│   ├── advanced_features.cpp     # Advanced features
│   ├── simple_password_manager.cpp # Simple manager
│   └── phase*_test.cpp           # Test programs
├── build_*.bat                   # Build scripts
├── create_installer.bat          # Installer creation
├── CMakeLists.txt               # Build configuration
├── README.md                    # This file
├── README_ADVANCED.md           # Advanced features guide
├── FEATURES_SUMMARY.md          # Features overview
├── ADVANCED_FEATURES_SUMMARY.md # Advanced features details
├── QR_CODE_GUIDE.md             # QR code usage guide
├── QR_IMPLEMENTATION_SUMMARY.md # QR implementation details
├── INSTALL.md                   # Installation guide
└── passwords.dat                # Encrypted password storage (created after first use)
```

## Password Strength Analysis

The password strength checker evaluates passwords based on:
- **Length**: Longer passwords get higher scores
- **Character Variety**: Mix of lowercase, uppercase, digits, symbols
- **Pattern Detection**: Penalties for consecutive or repeated characters
- **Minimum Requirements**: 8+ characters recommended
- **Breach Detection**: Check against known compromised passwords

Strength levels:
- **Very Weak** (0-19): Use at least 8 characters with mixed case, numbers, and symbols
- **Weak** (20-39): Add more variety and length
- **Medium** (40-59): Consider adding special characters and increasing length
- **Strong** (60-79): Good job!
- **Very Strong** (80-100): Excellent security!

## Advanced Features

### Two-Factor Authentication (TOTP)
- Generate TOTP secrets for services
- QR code generation for easy setup
- Time-based one-time password verification
- Compatible with Google Authenticator, Authy, etc.

### Password Sharing
- **Text-based sharing**: Encrypted text for manual sharing
- **File sharing**: Encrypted files with expiry
- **Link sharing**: Encoded data in shareable links
- **Email templates**: Pre-formatted email templates

### QR Code Generation
- Generate QR codes for password data
- ASCII QR patterns for terminal display
- Online QR code URLs for easy scanning
- Encrypted QR code data

### Smart Categories & Tags
- Organize passwords with custom categories
- Add tags for better searchability
- Filter passwords by category or tag
- Bulk operations on categorized passwords

### Self-Destruct Mode
- Emergency data deletion
- Configurable triggers (failed attempts, time limits)
- Secure file overwriting
- Audit logging

### Password Recovery
- Recovery code generation
- Backup and restore functionality
- Emergency access mechanisms
- Data export for recovery

## Troubleshooting

### Common Issues

#### Build Errors
- **OpenSSL not found**: Use the simple build script for dependency-free version
- **Compiler errors**: Make sure you have a C++11 compatible compiler
- **Linker errors**: Check that OpenSSL libraries are properly linked (for AES version)

#### Runtime Errors
- **File permission errors**: Ensure write permissions in the application directory
- **Memory errors**: Check available system memory
- **Encryption errors**: Verify OpenSSL installation (for AES version)

### Getting Help
If you encounter issues:
1. Try the simple build script first (`build_simple.bat`)
2. Check that your compiler supports C++11
3. For AES features, ensure OpenSSL is correctly linked
4. Check file permissions in the application directory

## Contributing

This is a comprehensive learning project demonstrating:
- C++11 features and STL usage
- Cryptographic programming with multiple encryption methods
- File I/O and data persistence
- CLI application design with advanced features
- Security best practices and modern authentication
- QR code generation and data sharing
- Two-factor authentication implementation

Feel free to extend the functionality or improve the security features!

## License

This project is for educational purposes. Use at your own risk and ensure you understand the security implications of storing sensitive data.

## Disclaimer

This password manager is designed for educational purposes. For production use, consider established password managers like KeePass, Bitwarden, or 1Password that have undergone extensive security audits.
