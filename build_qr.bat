@echo off
echo Building Password Manager with QR Code Sharing...

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_qr.exe ^
    src/main_simple.cpp ^
    src/simple_password_manager.cpp ^
    src/simple_encryption.cpp ^
    src/password_strength.cpp ^
    src/simple_utils.cpp ^
    src/qr_code.cpp

if %errorlevel% equ 0 (
    echo.
    echo ✅ Build successful!
    echo.
    echo 🚀 QR Code Password Manager Features:
    echo - Password sharing via QR codes
    echo - Optional password protection for QR codes
    echo - Configurable expiry times
    echo - Secure import functionality
    echo - ASCII QR pattern generation
    echo - Base64 encoding/decoding
    echo - XOR encryption for protection
    echo - Unique share ID generation
    echo - Timestamp tracking
    echo - Data validation
    echo.
    echo 📱 Usage:
    echo - Run: pwd_manager_qr.exe
    echo - Menu options 16-17 for QR functionality
    echo.
    echo 📖 Documentation: QR_CODE_GUIDE.md
) else (
    echo ❌ Build failed!
    echo.
    echo 🔧 Troubleshooting:
    echo - Check if all source files exist
    echo - Verify C++17 compiler support
    echo - Ensure include directory is correct
)

pause
