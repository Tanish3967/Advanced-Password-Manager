# Installation Guide

## Quick Start (Simple Version - No OpenSSL Required)

### Windows
1. **Install MinGW-w64** (if not already installed):
   - Download from: https://www.mingw-w64.org/
   - Or use MSYS2: https://www.msys2.org/

2. **Build the simple version**:
   ```cmd
   build_simple.bat
   ```

3. **Run the password manager**:
   ```cmd
   pwd_manager_simple.exe
   ```

### Linux/macOS
1. **Install dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install build-essential

   # macOS
   brew install gcc
   ```

2. **Build the simple version**:
   ```bash
   g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager_simple src/main.cpp src/simple_password_manager.cpp src/simple_encryption.cpp src/password_strength.cpp src/utils.cpp
   ```

3. **Run the password manager**:
   ```bash
   ./pwd_manager_simple
   ```

## Full Version (With OpenSSL - Recommended for Security)

### Windows

#### Option 1: Using vcpkg (Recommended)
```cmd
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# Install OpenSSL
.\vcpkg install openssl

# Build with CMake
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

#### Option 2: Manual OpenSSL Installation
1. **Download OpenSSL**:
   - Visit: https://slproweb.com/products/Win32OpenSSL.html
   - Download the latest Win64 version

2. **Install OpenSSL**:
   - Run the installer
   - Add OpenSSL bin directory to PATH

3. **Build the project**:
   ```cmd
   build.bat
   ```

### Linux

#### Ubuntu/Debian
```bash
# Install dependencies
sudo apt update
sudo apt install build-essential cmake libssl-dev

# Build with CMake
mkdir build
cd build
cmake ..
make

# Or build directly
g++ -std=c++17 -Wall -Wextra -O2 -Iinclude -o pwd_manager src/*.cpp -lssl -lcrypto
```

#### CentOS/RHEL/Fedora
```bash
# Install dependencies
sudo yum install gcc-c++ cmake openssl-devel
# or for Fedora: sudo dnf install gcc-c++ cmake openssl-devel

# Build
mkdir build
cd build
cmake ..
make
```

### macOS

#### Using Homebrew
```bash
# Install dependencies
brew install cmake openssl

# Build
mkdir build
cd build
cmake ..
make
```

#### Using MacPorts
```bash
# Install dependencies
sudo port install cmake openssl3

# Build
mkdir build
cd build
cmake ..
make
```

## Verification

After building, you should see:
- `pwd_manager.exe` (Windows) or `pwd_manager` (Linux/macOS) - Full version with OpenSSL
- `pwd_manager_simple.exe` (Windows) or `pwd_manager_simple` (Linux/macOS) - Simple version

## Troubleshooting

### Common Build Errors

#### "g++ not found"
- **Windows**: Install MinGW-w64 or Visual Studio
- **Linux**: Install build-essential package
- **macOS**: Install Xcode Command Line Tools

#### "OpenSSL not found"
- Install OpenSSL development libraries
- Ensure OpenSSL is in your PATH
- Use the simple version if OpenSSL is not available

#### "C++17 not supported"
- Update your compiler to a C++17 compatible version
- GCC 7+, Clang 5+, or MSVC 2017+

#### Linker Errors
- Ensure OpenSSL libraries are properly linked
- Check library paths and include directories

### Platform-Specific Issues

#### Windows
- **MinGW**: Ensure you're using MinGW-w64, not the old MinGW
- **Visual Studio**: Install the C++ development workload
- **PATH Issues**: Add compiler and OpenSSL directories to PATH

#### Linux
- **Permission Denied**: Use `chmod +x pwd_manager` to make executable
- **Library Not Found**: Install development packages (`-dev` or `-devel`)

#### macOS
- **Xcode**: Install Xcode Command Line Tools: `xcode-select --install`
- **Homebrew**: Ensure Homebrew is properly installed and updated

## Security Notice

### Simple Version
- Uses basic XOR encryption for demonstration
- **NOT suitable for storing real passwords**
- Use only for learning and testing

### Full Version
- Uses AES-256-CBC encryption with OpenSSL
- Suitable for storing real passwords
- Follows security best practices

## Next Steps

1. **First Run**: The password manager will prompt you to create a master password
2. **Add Passwords**: Use the menu to add your first password
3. **Test Features**: Try password strength checking and generation
4. **Backup**: Keep a backup of your `passwords.dat` file

## Support

If you encounter issues:
1. Check this installation guide
2. Verify all dependencies are installed
3. Try the simple version first
4. Check compiler and library versions
