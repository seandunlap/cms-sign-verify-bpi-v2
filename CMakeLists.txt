# CMakeLists.txt: Builds cms_sign_verify.c with OpenSSL dependency
# Minimum CMake version: 3.10
# Dependencies: OpenSSL (downloaded and built), C11 compiler
# Output: cms_sign_verify executable
# Usage: cmake -S . -B build && cmake --build build

cmake_minimum_required(VERSION 3.10)

# Project name and version
project(cms_sign_verify VERSION 1.0 LANGUAGES C)

# Specify the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Option for verbose output
option(ENABLE_VERBOSE_OUTPUT "Enable verbose makefile output" ON)
if(ENABLE_VERBOSE_OUTPUT)
    set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Enable verbose makefile output" FORCE)
endif()

# Custom debug message function
function(debug_message)
    message(STATUS "[DEBUG] ${ARGN}")
endfunction()

# Custom progress message function
function(progress_message)
    message(STATUS "[PROGRESS] ${ARGN}")
endfunction()

# Include ExternalProject module for downloading OpenSSL
include(ExternalProject)

# Define OpenSSL version and download details
set(OPENSSL_VERSION "3.4.0")
set(OPENSSL_URL "https://github.com/openssl/openssl/archive/refs/tags/openssl-${OPENSSL_VERSION}.tar.gz")
set(OPENSSL_FALLBACK_URL "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz")
set(OPENSSL_HASH "SHA256=1ca043a26fbea74cdf7faf623a6f14032a01117d141c4a5208ccac819ccc896b")
set(OPENSSL_PREFIX "${CMAKE_BINARY_DIR}/openssl")
set(OPENSSL_INSTALL_DIR "${OPENSSL_PREFIX}/install")

# Debug: Print OpenSSL configuration
debug_message("OpenSSL Version: ${OPENSSL_VERSION}")
debug_message("OpenSSL URL: ${OPENSSL_URL}")
debug_message("OpenSSL Fallback URL: ${OPENSSL_FALLBACK_URL}")
debug_message("OpenSSL Hash: ${OPENSSL_HASH}")
debug_message("OpenSSL Prefix: ${OPENSSL_PREFIX}")
debug_message("OpenSSL Install Dir: ${OPENSSL_INSTALL_DIR}")

# Configure OpenSSL build based on platform
if(WIN32)
    find_program(PERL_EXECUTABLE perl)
    if(NOT PERL_EXECUTABLE)
        message(FATAL_ERROR "Perl is required for OpenSSL build on Windows")
    endif()
    set(OPENSSL_CONFIGURE_COMMAND ${PERL_EXECUTABLE} Configure VC-WIN64A --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}/ssl no-shared)
    set(OPENSSL_BUILD_COMMAND nmake)
    set(OPENSSL_INSTALL_COMMAND nmake install)
else()
    set(OPENSSL_CONFIGURE_COMMAND ./config --prefix=${OPENSSL_INSTALL_DIR} --openssldir=${OPENSSL_INSTALL_DIR}/ssl no-shared)
    set(OPENSSL_BUILD_COMMAND make -j${CMAKE_BUILD_PARALLEL_LEVEL})
    set(OPENSSL_INSTALL_COMMAND make install)
endif()

# Configure ExternalProject to download and build OpenSSL
ExternalProject_Add(
    openssl
    URL ${OPENSSL_URL}
    URL_HASH ${OPENSSL_HASH}
    PREFIX ${OPENSSL_PREFIX}
    CONFIGURE_COMMAND
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] Starting OpenSSL configuration"
        COMMAND ${OPENSSL_CONFIGURE_COMMAND}
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] OpenSSL configuration completed"
    BUILD_COMMAND
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] Starting OpenSSL build"
        COMMAND ${OPENSSL_BUILD_COMMAND}
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] OpenSSL build completed"
    INSTALL_COMMAND
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] Starting OpenSSL installation"
        COMMAND ${OPENSSL_INSTALL_COMMAND}
        COMMAND ${CMAKE_COMMAND} -E echo "[PROGRESS] OpenSSL installation completed"
    BUILD_IN_SOURCE 1
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
    LOG_DOWNLOAD ON
    LOG_UPDATE ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    LOG_OUTPUT_ON_FAILURE ON
)

# Set OpenSSL include and library directories
set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include")
set(OPENSSL_LIBRARY_DIR "${OPENSSL_INSTALL_DIR}/lib")
set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARY_DIR}/libssl.a" "${OPENSSL_LIBRARY_DIR}/libcrypto.a")
set(OPENSSL_BINARY "${OPENSSL_INSTALL_DIR}/bin/openssl")

# Debug: Print OpenSSL paths
debug_message("OpenSSL Include Dir: ${OPENSSL_INCLUDE_DIR}")
debug_message("OpenSSL Library Dir: ${OPENSSL_LIBRARY_DIR}")
debug_message("OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
debug_message("OpenSSL Binary: ${OPENSSL_BINARY}")

# Define input/output files for cms_sign_verify
set(CERT_FILE "${CMAKE_SOURCE_DIR}/cm_device_cert.der")
set(KEY_FILE "${CMAKE_SOURCE_DIR}/cm_device_private.pem")
set(INPUT_FILE "${CMAKE_SOURCE_DIR}/auth_request_data.bin")
set(OUTPUT_FILE "${CMAKE_SOURCE_DIR}/cms-computed-by-C-code.der")

# Define the executable target
add_executable(cms_sign_verify cms_sign_verify.c)
debug_message("Added executable target: cms_sign_verify")

# Add dependency on OpenSSL
add_dependencies(cms_sign_verify openssl)
debug_message("Added dependency: cms_sign_verify depends on openssl")

# Include directories for OpenSSL
target_include_directories(cms_sign_verify PRIVATE ${OPENSSL_INCLUDE_DIR})
debug_message("Include directories for cms_sign_verify: ${OPENSSL_INCLUDE_DIR}")

# Link OpenSSL libraries
target_link_libraries(cms_sign_verify PRIVATE ${OPENSSL_LIBRARIES})
debug_message("Linked libraries for cms_sign_verify: ${OPENSSL_LIBRARIES}")

# Link additional system libraries if needed
if(UNIX AND NOT APPLE)
    target_link_libraries(cms_sign_verify PRIVATE dl pthread)
    debug_message("Linked additional Linux libraries: dl, pthread")
elseif(WIN32)
    target_link_libraries(cms_sign_verify PRIVATE ws2_32 crypt32)
    debug_message("Linked additional Windows libraries: ws2_32, crypt32")
elseif(APPLE)
    target_link_libraries(cms_sign_verify PRIVATE "-framework Security" "-framework CoreFoundation")
    debug_message("Linked additional macOS libraries: Security, CoreFoundation")
endif()

# Pass file paths to the C program
target_compile_definitions(cms_sign_verify PRIVATE
    CERT_FILE="${CERT_FILE}"
    KEY_FILE="${KEY_FILE}"
    INPUT_FILE="${INPUT_FILE}"
    OUTPUT_FILE="${OUTPUT_FILE}"
)
debug_message("Defined file paths: CERT_FILE=${CERT_FILE}, KEY_FILE=${KEY_FILE}, INPUT_FILE=${INPUT_FILE}, OUTPUT_FILE=${OUTPUT_FILE}")

# Add clean target for OpenSSL build artifacts
set_directory_properties(PROPERTIES ADDITIONAL_CLEAN_FILES "${OPENSSL_PREFIX};${CMAKE_BINARY_DIR}/cms_sign_verify")
debug_message("Set additional clean files: ${OPENSSL_PREFIX}, ${CMAKE_BINARY_DIR}/cms_sign_verify")

# Custom target to validate OpenSSL installation after build
add_custom_target(validate_openssl
    COMMAND ${CMAKE_COMMAND} -E echo "Validating OpenSSL installation..."
    COMMAND ${CMAKE_COMMAND}
        -DOPENSSL_LIBRARY_DIR=${OPENSSL_LIBRARY_DIR}
        -DOPENSSL_BINARY=${OPENSSL_BINARY}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/validate_openssl.cmake
    DEPENDS openssl
    COMMENT "Validating OpenSSL libraries and binary"
)
add_dependencies(cms_sign_verify validate_openssl)
debug_message("Added custom target: validate_openssl")