# Advanced Password Manager

A feature-rich CLI-based password manager written in C++ with advanced security and management capabilities.

## 🚀 New Advanced Features

### 1. Password Expiry Tracking
- **Set expiry dates** for passwords (YYYY-MM-DD format)
- **View expired passwords** that need immediate attention
- **Monitor expiring passwords** within a specified timeframe
- **Update expiry dates** for existing passwords
- **Automatic expiry detection** and warnings

### 2. Password History
- **Track password changes** automatically
- **View previous passwords** (masked for security)
- **Maintain last 10 passwords** in history
- **Prevent password reuse** by showing history
- **Secure storage** of historical passwords

### 3. Enhanced Search & Organization
- **Category-based organization** for passwords
- **Advanced search** across service, username, and notes
- **Category filtering** in search results
- **Favorites system** for quick access to important passwords
- **Duplicate detection** to identify reused passwords

### 4. Password Strength Visualization
- **Visual strength bars** with color coding
- **Detailed strength analysis** with scores (0-100)
- **Real-time feedback** on password improvements
- **Strength ratings**: Very Weak, Weak, Medium, Strong, Very Strong
- **Specific recommendations** for improvement

### 5. Advanced Password Generation
- **Customizable length** (default 16 characters)
- **Character set options**: Uppercase, Lowercase, Digits, Symbols
- **Exclude similar characters** (0/O, 1/l/I, etc.)
- **Custom character sets** for specific requirements
- **Strength validation** of generated passwords

### 6. Breach Monitoring
- **Check against common breached passwords**
- **Simulated breach detection** (can be extended with real APIs)
- **Breach count reporting**
- **Security recommendations** for compromised passwords
- **Last check timestamps**

### 7. QR Code Generation
- **Text-based QR patterns** for password sharing
- **Mobile-friendly format** for easy scanning
- **Encrypted QR data** for security
- **Password sharing via QR codes**
- **Cross-platform compatibility**

### 8. Password Health Analysis
- **Overall password health score**
- **Category distribution analysis**
- **Duplicate password detection**
- **Expiry status overview**
- **Security recommendations**

## 📋 Menu Options

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
9. Change Master Password
10. Logout
11. Password Expiry Management
12. Password History
13. Manage Categories
14. Find Duplicate Passwords
15. Favorites Management
0. Exit
```

## 🔧 Building the Advanced Version

### Prerequisites
- C++17 compatible compiler (GCC, Clang, or MSVC)
- Windows, Linux, or macOS

### Build Commands

**Windows (MinGW):**
```bash
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_advanced_v2.exe ^
    src/main_simple.cpp ^
    src/simple_password_manager.cpp ^
    src/simple_encryption.cpp ^
    src/password_strength.cpp ^
    src/simple_utils.cpp
```

**Linux/macOS:**
```bash
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_advanced_v2 ^
    src/main_simple.cpp \
    src/simple_password_manager.cpp \
    src/simple_encryption.cpp \
    src/password_strength.cpp \
    src/simple_utils.cpp
```

### Quick Build Script
```bash
# Windows
build_advanced.bat

# Linux/macOS
make advanced
```

## 🛡️ Security Features

### Encryption
- **XOR-based encryption** for data storage
- **Master password hashing** with salt
- **Encrypted password history**
- **Secure file I/O** operations

### Data Protection
- **Hidden password input** (no echo)
- **Encrypted storage** of all sensitive data
- **Session management** with logout capability
- **Secure memory handling**

## 📊 Data Structure

### Password Entry Fields
```cpp
struct PasswordEntry {
    std::string service;           // Service/website name
    std::string username;          // Username/email
    std::string password;          // Encrypted password
    std::string notes;             // Additional notes
    std::string category;          // Organization category
    std::string expiry_date;       // Password expiry date
    bool is_favorite;              // Favorite status
    std::vector<std::string> password_history; // Previous passwords
    std::string created_date;      // Creation timestamp
    std::string modified_date;     // Last modification
};
```

## 🎯 Usage Examples

### Adding a Password with Advanced Features
```
Enter service name: GitHub
Enter username: user@example.com
Enter password: ********
Enter notes (optional): Personal account
Enter category (optional): Development
Enter expiry date (YYYY-MM-DD, optional): 2024-12-31
```

### Password Expiry Management
```
=== Password Expiry Management ===
1. View expired passwords
2. View passwords expiring soon
3. Update password expiry
```

### Category Management
```
=== Category Management ===
1. View all categories
2. Search by category
```

### Favorites Management
```
=== Favorites Management ===
1. View favorite passwords
2. Toggle favorite status
```

## 🔍 Search Capabilities

### Basic Search
- Search by service name
- Search by username
- Search by notes content
- Case-insensitive matching

### Advanced Search
- Category-based filtering
- Favorite-only filtering
- Combined search terms
- Partial matching support

## 📈 Password Strength Analysis

### Strength Levels
- **Very Weak (0-20)**: 🔴 Immediate change required
- **Weak (21-40)**: 🟠 Should be improved
- **Medium (41-60)**: 🟡 Acceptable but could be better
- **Strong (61-80)**: 🟢 Good security level
- **Very Strong (81-100)**: 🟢 Excellent security

### Analysis Factors
- Length and complexity
- Character variety
- Common patterns detection
- Dictionary word checking
- Sequential character detection

## 🔄 Password History Features

### Automatic Tracking
- Stores last 10 passwords per account
- Prevents accidental reuse
- Secure encrypted storage
- Timestamp tracking

### History Management
- View masked password history
- Automatic cleanup of old entries
- Secure deletion of history

## 🎨 QR Code Features

### Generation
- Text-based QR patterns
- Encrypted data format
- Mobile-friendly encoding
- Cross-platform compatibility

### Sharing
- Secure password sharing
- Encrypted QR data
- Temporary access codes
- Expiry-based sharing

## 🏥 Password Health Analysis

### Health Metrics
- Overall password strength score
- Duplicate password detection
- Expiry status overview
- Category distribution
- Security recommendations

### Health Ratings
- **Excellent (80-100)**: 🟢 Optimal security
- **Good (60-79)**: 🟡 Good with room for improvement
- **Fair (40-59)**: 🟠 Needs attention
- **Poor (20-39)**: 🔴 Requires immediate action
- **Very Poor (0-19)**: 🔴 Critical security issues

## 🔧 Configuration Options

### Password Generation Rules
```cpp
struct PasswordGeneratorRules {
    int length = 16;                    // Password length
    bool use_uppercase = true;          // Include uppercase letters
    bool use_lowercase = true;          // Include lowercase letters
    bool use_digits = true;             // Include numbers
    bool use_symbols = true;            // Include special characters
    bool exclude_similar = false;       // Exclude similar characters
    std::string custom_chars = "";      // Custom character set
};
```

## 📁 File Structure

```
pswrd_mang/
├── include/
│   ├── password_manager.h          # Main password manager interface
│   ├── password_strength.h         # Password strength checking
│   ├── simple_encryption.h         # Encryption utilities
│   └── utils.h                     # General utilities
├── src/
│   ├── main_simple.cpp             # Main application (advanced features)
│   ├── simple_password_manager.cpp # Password manager implementation
│   ├── simple_encryption.cpp       # Encryption implementation
│   ├── password_strength.cpp       # Strength checking implementation
│   └── simple_utils.cpp            # Utility functions
├── pwd_manager_advanced_v2.exe     # Executable
├── passwords.dat                   # Encrypted password database
└── README_ADVANCED.md              # This file
```

## 🚀 Future Enhancements

### Planned Features
- **Real-time breach monitoring** with API integration
- **Two-factor authentication** support
- **Cloud synchronization** capabilities
- **Browser extension** integration
- **Advanced encryption** (AES-256)
- **Backup and restore** functionality
- **Password sharing** with expiration
- **Audit logging** for security events

### API Integration Possibilities
- **HaveIBeenPwned API** for real breach checking
- **Password strength APIs** for enhanced validation
- **Cloud storage APIs** for synchronization
- **Email APIs** for password expiry notifications

## 🤝 Contributing

This password manager is designed to be extensible. Key areas for contribution:

1. **Enhanced encryption** algorithms
2. **Additional password generation** strategies
3. **Improved UI/UX** features
4. **API integrations** for external services
5. **Cross-platform** compatibility improvements
6. **Performance optimizations**

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Security Disclaimer

This password manager uses simplified encryption for demonstration purposes. For production use, consider:

- Implementing stronger encryption (AES-256)
- Adding additional security layers
- Regular security audits
- Professional security review
- Integration with hardware security modules (HSM)

---

**Built with ❤️ using C++17 and modern security practices**
