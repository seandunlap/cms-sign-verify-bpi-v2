# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(authReqSignature VERSION 1.0 LANGUAGES C)

# Specify the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include ExternalProject module for downloading OpenSSL
include(ExternalProject)

# Define OpenSSL version and download details
set(OPENSSL_VERSION "3.4.0")
set(OPENSSL_URL "https://github.com/openssl/openssl/archive/refs/tags/openssl-${OPENSSL_VERSION}.tar.gz")
set(OPENSSL_PREFIX "${CMAKE_BINARY_DIR}/openssl")
set(OPENSSL_INSTALL_DIR "${OPENSSL_PREFIX}/install")

# Configure ExternalProject to download and build OpenSSL
ExternalProject_Add(
    openssl
    URL ${OPENSSL_URL}
    PREFIX ${OPENSSL_PREFIX}
    CONFIGURE_COMMAND ${OPENSSL_PREFIX}/src/openssl/config --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}/ssl no-shared
    BUILD_COMMAND make
    INSTALL_COMMAND make install_sw
    BUILD_IN_SOURCE 1
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE # Use extraction time for timestamps (NEW behavior)
)

# Set OpenSSL include and library directories
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
set(OPENSSL_LIBRARY_DIR "${OPENSSL_INSTALL_DIR}/lib")
set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARY_DIR}/libssl.a" "${OPENSSL_LIBRARY_DIR}/libcrypto.a")

# Ensure the OpenSSL include directory exists
file(MAKE_DIRECTORY ${OPENSSL_INCLUDE_DIR})

# Define the executable target
add_executable(authReqSignature authReqSignature.c)

# Add dependency on OpenSSL
add_dependencies(authReqSignature openssl)

# Include directories for OpenSSL
target_include_directories(authReqSignature PRIVATE ${OPENSSL_INCLUDE_DIR})

# Link OpenSSL libraries
target_link_libraries(authReqSignature PRIVATE ${OPENSSL_LIBRARIES})

# Link additional system libraries if needed (e.g., for Linux)
if(UNIX AND NOT APPLE)
    target_link_libraries(authReqSignature PRIVATE dl pthread)
endif()

# Add clean target (optional)
set_directory_properties(PROPERTIES ADDITIONAL_CLEAN_FILES authReqSignature)