cmake_minimum_required(VERSION 3.25)

project(UnlockWindowsWithIPhone LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "The Windows targets must be configured on Windows.")
endif()

add_library(unlock_protocol_crypto STATIC
    Protocol/UnlockCrypto.cpp
    Protocol/SigningPayload.cpp
)

target_include_directories(unlock_protocol_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
)

target_compile_features(unlock_protocol_crypto PUBLIC cxx_std_20)
target_compile_definitions(unlock_protocol_crypto PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_protocol_crypto PUBLIC bcrypt)

# GattHost, UnlockService, CredentialProvider and LSAAuthenticationPackage are
# intentionally separate targets. They will be added only when each target has
# an explicit installation and failure policy.
