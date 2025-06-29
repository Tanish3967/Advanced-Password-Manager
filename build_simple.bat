@echo off
echo Building Simple Password Manager...

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_simple.exe src/main.cpp src/simple_password_manager.cpp src/simple_encryption.cpp src/password_strength.cpp src/simple_utils.cpp

if %errorlevel% equ 0 (
    echo Build successful!
    echo.
    echo WARNING: This version uses simple XOR encryption for demonstration.
    echo DO NOT use this for storing real passwords - it is NOT secure!
    echo.
    echo Run: pwd_manager_simple.exe
) else (
    echo Build failed!
    echo Check that you have a C++17 compatible compiler.
)

pause
