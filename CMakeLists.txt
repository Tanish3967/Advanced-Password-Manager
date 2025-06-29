cmake_minimum_required(VERSION 3.10)
project(PasswordManager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(pwd_manager
    src/main.cpp
    src/password_manager.cpp
    src/encryption.cpp
    src/password_strength.cpp
    src/utils.cpp
)

# Include directories
target_include_directories(pwd_manager PRIVATE include)

# Link libraries
target_link_libraries(pwd_manager OpenSSL::SSL OpenSSL::Crypto)

# Set compiler flags
if(MSVC)
    target_compile_options(pwd_manager PRIVATE /W4)
else()
    target_compile_options(pwd_manager PRIVATE -Wall -Wextra -Wpedantic)
endif()
