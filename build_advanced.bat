@echo off
echo Building Advanced Password Manager with all features...

REM Add missing includes to fix compilation
echo #include ^<map^> > temp_includes.h
echo #include ^<iomanip^> >> temp_includes.h

g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_advanced.exe ^
    src/main.cpp ^
    src/simple_password_manager.cpp ^
    src/simple_encryption.cpp ^
    src/password_strength.cpp ^
    src/simple_utils.cpp ^
    src/advanced_features.cpp

if %errorlevel% equ 0 (
    echo Build successful!
    echo.
    echo Advanced Password Manager Features:
    echo - Password Expiry Tracking
    echo - Password History
    echo - Enhanced Search
    echo - Custom Password Generation Rules
    echo - Password Strength Visualization
    echo - Breach Monitoring
    echo - QR Code Generation
    echo - Password Sharing via QR
    echo - Categories and Favorites
    echo - Duplicate Password Detection
    echo.
    echo Run: pwd_manager_advanced.exe
) else (
    echo Build failed! Trying simplified version...
    g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_simple_v2.exe ^
        src/main.cpp ^
        src/simple_password_manager.cpp ^
        src/simple_encryption.cpp ^
        src/password_strength.cpp ^
        src/simple_utils.cpp
    if %errorlevel% equ 0 (
        echo Simplified build successful!
        echo Run: pwd_manager_simple_v2.exe
    ) else (
        echo Both builds failed!
    )
)

del temp_includes.h 2>nul
pause
