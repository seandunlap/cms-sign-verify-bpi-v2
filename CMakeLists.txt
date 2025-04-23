cmake_minimum_required(VERSION 3.10)
project(cms_sign_verify VERSION 1.0 LANGUAGES C)

# — Use C11 —
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# — Optional verbose makefile output —
option(ENABLE_VERBOSE_OUTPUT "Enable verbose makefile output" ON)
if(ENABLE_VERBOSE_OUTPUT)
  set(CMAKE_VERBOSE_MAKEFILE ON)
endif()

# — Logging helpers —
function(debug_message)
  message(STATUS "[DEBUG] ${ARGN}")
endfunction()
function(progress_message)
  message(STATUS "[PROGRESS] ${ARGN}")
endfunction()

# ----------------------------------------------------------------------------
# 1) ExternalProject: download, configure, build & install OpenSSL
# ----------------------------------------------------------------------------
include(ExternalProject)

set(OPENSSL_VERSION     "3.4.0")
set(OPENSSL_BASE_DIR    "${CMAKE_BINARY_DIR}/third_party/openssl")
set(OPENSSL_SRC_DIR     "${OPENSSL_BASE_DIR}/src/openssl-${OPENSSL_VERSION}")
set(OPENSSL_INSTALL_DIR "${OPENSSL_BASE_DIR}/install")

debug_message("OpenSSL version: ${OPENSSL_VERSION}")
debug_message("Installing OpenSSL under: ${OPENSSL_INSTALL_DIR}")

ExternalProject_Add(openssl
  PREFIX         "${OPENSSL_BASE_DIR}"
  URL            "https://github.com/openssl/openssl/archive/refs/tags/openssl-${OPENSSL_VERSION}.tar.gz"
  URL_HASH       "SHA256=1ca043a26fbea74cdf7faf623a6f14032a01117d141c4a5208ccac819ccc896b"

  DOWNLOAD_DIR   "${OPENSSL_BASE_DIR}/download"
  SOURCE_DIR     "${OPENSSL_SRC_DIR}"
  BINARY_DIR     "${OPENSSL_SRC_DIR}"
  INSTALL_DIR    "${OPENSSL_INSTALL_DIR}"
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE

  # — Configure step (runs in BINARY_DIR, which == SOURCE_DIR) —
  CONFIGURE_COMMAND
    ${OPENSSL_SRC_DIR}/config
      --prefix=${OPENSSL_INSTALL_DIR}
      --openssldir=${OPENSSL_INSTALL_DIR}/ssl
      no-shared

  # — Build step (use shell to chain commands) —
  BUILD_COMMAND
    ${CMAKE_COMMAND} -E env sh -c
      "make -C ${OPENSSL_SRC_DIR} depend && make -C ${OPENSSL_SRC_DIR}"

  # — Install step —
  INSTALL_COMMAND
    make -C "${OPENSSL_SRC_DIR}" install

  LOG_DOWNLOAD          ON
  LOG_CONFIGURE         ON
  LOG_BUILD             ON
  LOG_INSTALL           ON
  LOG_OUTPUT_ON_FAILURE ON
)

# ----------------------------------------------------------------------------
# 2) Import the freshly built static libs
# ----------------------------------------------------------------------------
add_library(ssl_lib STATIC IMPORTED GLOBAL)
set_target_properties(ssl_lib PROPERTIES
  IMPORTED_LOCATION "${OPENSSL_INSTALL_DIR}/lib/libssl.a"
)

add_library(crypto_lib STATIC IMPORTED GLOBAL)
set_target_properties(crypto_lib PROPERTIES
  IMPORTED_LOCATION "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a"
)

# Ensure our import happens after openssl is built
add_dependencies(ssl_lib   openssl)
add_dependencies(crypto_lib openssl)

# ----------------------------------------------------------------------------
# 3) Build your cms_sign_verify program against those libs
# ----------------------------------------------------------------------------
add_executable(cms_sign_verify cms_sign_verify.c)

# Make sure OpenSSL is ready first
add_dependencies(cms_sign_verify ssl_lib crypto_lib)

# Add the install include dir manually (no INTERFACE on the imported libs)
target_include_directories(cms_sign_verify PRIVATE
  "${OPENSSL_INSTALL_DIR}/include"
)

target_link_libraries(cms_sign_verify PRIVATE
  ssl_lib
  crypto_lib
)

# Link any extra system libs per platform
if(UNIX AND NOT APPLE)
  target_link_libraries(cms_sign_verify PRIVATE dl pthread)
elseif(APPLE)
  target_link_libraries(cms_sign_verify PRIVATE
    "-framework Security"
    "-framework CoreFoundation"
  )
elseif(WIN32)
  target_link_libraries(cms_sign_verify PRIVATE ws2_32 crypt32)
endif()

# ----------------------------------------------------------------------------
# 4) Pass your file-path macros into the C code
# ----------------------------------------------------------------------------
target_compile_definitions(cms_sign_verify PRIVATE
  CERT_FILE="${CMAKE_SOURCE_DIR}/cm_device_cert.der"
  KEY_FILE="${CMAKE_SOURCE_DIR}/cm_device_private.pem"
  INPUT_FILE="${CMAKE_SOURCE_DIR}/auth_request_data.bin"
  OUTPUT_FILE="${CMAKE_SOURCE_DIR}/cms-computed-by-C-code.der"
)
