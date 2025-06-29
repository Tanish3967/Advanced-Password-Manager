@echo off
echo Building Password Manager...

REM Check if we have a C++ compiler
where g++ >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: g++ not found. Please install MinGW or use Visual Studio.
    echo For MinGW: https://www.mingw-w64.org/
    echo For Visual Studio: https://visualstudio.microsoft.com/
    pause
    exit /b 1
)

REM Check if OpenSSL is available
where openssl >nul 2>nul
if %errorlevel% neq 0 (
    echo Warning: OpenSSL not found in PATH.
    echo Please install OpenSSL: https://slproweb.com/products/Win32OpenSSL.html
    echo Or use vcpkg: vcpkg install openssl
)

REM Create build directory
if not exist build mkdir build
cd build

REM Try to build with CMake first
where cmake >nul 2>nul
if %errorlevel% equ 0 (
    echo Using CMake build system...
    cmake ..
    if %errorlevel% equ 0 (
        cmake --build .
        if %errorlevel% equ 0 (
            echo Build successful!
            echo Run: pwd_manager.exe
            cd ..
            pause
            exit /b 0
        )
    )
)

REM Fallback to direct compilation
echo Using direct compilation...
cd ..
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager.exe src/*.cpp -lssl -lcrypto
if %errorlevel% equ 0 (
    echo Build successful!
    echo Run: pwd_manager.exe
) else (
    echo Build failed!
    echo Make sure OpenSSL libraries are installed and linked properly.
)

pause
