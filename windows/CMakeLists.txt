cmake_minimum_required(VERSION 3.25)

project(UnlockWindowsWithIPhone LANGUAGES CXX)

include(CTest)

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

add_library(unlock_service_core STATIC
    UnlockService/UnlockServiceCore.cpp
)

target_include_directories(unlock_service_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_service_core PUBLIC cxx_std_20)
target_compile_definitions(unlock_service_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_service_core PUBLIC unlock_protocol_crypto windowsapp bcrypt)

if(BUILD_TESTING)
    add_executable(unlock_protocol_tests
        ProtocolTests/main.cpp
    )

    target_compile_features(unlock_protocol_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_protocol_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_protocol_tests PRIVATE unlock_protocol_crypto bcrypt)

    add_test(NAME unlock_protocol_tests COMMAND unlock_protocol_tests)

    add_executable(unlock_service_tests
        UnlockServiceTests/main.cpp
    )

    target_compile_features(unlock_service_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_service_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_service_tests PRIVATE unlock_service_core unlock_protocol_crypto windowsapp bcrypt)

    add_test(NAME unlock_service_tests COMMAND unlock_service_tests)
endif()

add_executable(unlock_gatt_host
    GattHost/main.cpp
)

target_compile_features(unlock_gatt_host PRIVATE cxx_std_20)
target_compile_definitions(unlock_gatt_host PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_gatt_host PRIVATE windowsapp bcrypt)

# UnlockService, CredentialProvider and LSAAuthenticationPackage remain
# intentionally separate targets. They will be added only when each target
# has an explicit installation and failure policy.
