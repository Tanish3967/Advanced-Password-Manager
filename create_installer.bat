@echo off
echo Creating Password Manager Installer Package...
echo =============================================

echo Step 1: Building the application...
g++ -std=c++11 -o PasswordManager.exe src/standalone_password_manager.cpp

if %ERRORLEVEL% NEQ 0 (
    echo ❌ Build failed! Cannot create installer.
    pause
    exit /b 1
)

echo Step 2: Creating installer directory...
if not exist "PasswordManager_Installer" mkdir "PasswordManager_Installer"

echo Step 3: Copying files...
copy "PasswordManager.exe" "PasswordManager_Installer\"
copy "README.md" "PasswordManager_Installer\" 2>nul
copy "FEATURES_SUMMARY.md" "PasswordManager_Installer\" 2>nul

echo Step 4: Creating README for installer...
echo # Password Manager - Portable Edition > "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo ## Installation >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo 1. Extract all files to any folder >> "PasswordManager_Installer\README.txt"
echo 2. Double-click PasswordManager.exe to run >> "PasswordManager_Installer\README.txt"
echo 3. No installation required - works on any Windows machine >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo ## Features >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo - Secure password storage with encryption >> "PasswordManager_Installer\README.txt"
echo - Categories and tags for organization >> "PasswordManager_Installer\README.txt"
echo - Password history and versioning >> "PasswordManager_Installer\README.txt"
echo - Password strength checking >> "PasswordManager_Installer\README.txt"
echo - Strong password generation >> "PasswordManager_Installer\README.txt"
echo - Recovery codes and security questions >> "PasswordManager_Installer\README.txt"
echo - Mobile export/import functionality >> "PasswordManager_Installer\README.txt"
echo - Self-destruct mode for security >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo ## First Run >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo On first run, you will be prompted to: >> "PasswordManager_Installer\README.txt"
echo 1. Set a master password >> "PasswordManager_Installer\README.txt"
echo 2. Generate recovery codes >> "PasswordManager_Installer\README.txt"
echo 3. Set up a security question >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo ## Security >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo - All passwords are encrypted locally >> "PasswordManager_Installer\README.txt"
echo - No data is sent to external servers >> "PasswordManager_Installer\README.txt"
echo - Self-destruct mode protects against unauthorized access >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo ## Support >> "PasswordManager_Installer\README.txt"
echo. >> "PasswordManager_Installer\README.txt"
echo For help, run the application and select "Help/About" from the menu. >> "PasswordManager_Installer\README.txt"

echo Step 5: Creating run script...
echo @echo off > "PasswordManager_Installer\Run_PasswordManager.bat"
echo echo Starting Password Manager... >> "PasswordManager_Installer\Run_PasswordManager.bat"
echo echo. >> "PasswordManager_Installer\Run_PasswordManager.bat"
echo PasswordManager.exe >> "PasswordManager_Installer\Run_PasswordManager.bat"
echo pause >> "PasswordManager_Installer\Run_PasswordManager.bat"

echo Step 6: Creating ZIP package...
powershell -command "Compress-Archive -Path 'PasswordManager_Installer\*' -DestinationPath 'PasswordManager_Portable.zip' -Force"

echo.
echo ✅ Installer package created successfully!
echo.
echo Files created:
echo - PasswordManager_Installer\ (folder with all files)
echo - PasswordManager_Portable.zip (compressed package)
echo.
echo To distribute:
echo 1. Send PasswordManager_Portable.zip to users
echo 2. Users extract and run PasswordManager.exe
echo 3. No installation required!
echo.
echo The application is completely portable and self-contained.
echo It will work on any Windows machine without additional dependencies.
echo.

pause
