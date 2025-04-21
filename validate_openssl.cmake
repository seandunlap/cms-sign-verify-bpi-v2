# validate_openssl.cmake: Validates OpenSSL libraries and binary after build

# Check if required variables are defined
if(NOT DEFINED OPENSSL_LIBRARY_DIR)
    message(FATAL_ERROR "OPENSSL_LIBRARY_DIR is not defined")
endif()
if(NOT DEFINED OPENSSL_BINARY)
    message(FATAL_ERROR "OPENSSL_BINARY is not defined")
endif()

# Check libraries
set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARY_DIR}/libssl.a;${OPENSSL_LIBRARY_DIR}/libcrypto.a")
foreach(lib ${OPENSSL_LIBRARIES})
    if(NOT EXISTS "${lib}")
        message(FATAL_ERROR "OpenSSL library not found: ${lib}")
    endif()
    message(STATUS "Found OpenSSL library: ${lib}")
endforeach()

# Check binary
if(NOT EXISTS "${OPENSSL_BINARY}")
    message(FATAL_ERROR "OpenSSL binary not found: ${OPENSSL_BINARY}")
endif()
message(STATUS "Found OpenSSL binary: ${OPENSSL_BINARY}")