@echo off
echo Building Portable Password Manager...
echo ====================================

echo Compiling main application...
g++ -std=c++11 -o PasswordManager.exe src/main_simple.cpp

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Build successful!
    echo.
    echo The portable application is ready:
    echo - PasswordManager.exe (main application)
    echo.
    echo To distribute:
    echo 1. Copy PasswordManager.exe to any folder
    echo 2. Run it - it will create passwords.dat automatically
    echo 3. No installation required - works on any Windows machine
    echo.
    echo Features included:
    echo - Secure password storage with encryption
    echo - Categories and tags
    echo - Password history
    echo - Password strength checking
    echo - Strong password generation
    echo - Recovery codes
    echo - Mobile export/import
    echo - Self-destruct mode
    echo.
) else (
    echo.
    echo ❌ Build failed!
    echo Please check the error messages above.
)

pause
