# Modified by Rui MA on 26 Sep 2026
# Modified by Codex on 26 Sep 2026

cmake_minimum_required(VERSION 3.25)

project(UnlockWindowsWithIPhone LANGUAGES CXX)

# Keep NMake response files in the build tree instead of using its inline
# temporary-file syntax. The repository path contains spaces, and compiler /
# linker temporary files are redirected by windows/Makefile to the root .tmp.
if(CMAKE_GENERATOR MATCHES "NMake")
    foreach(lang IN ITEMS C CXX)
        set(CMAKE_${lang}_USE_RESPONSE_FILE_FOR_INCLUDES 0 FORCE)
        foreach(command IN ITEMS
            COMPILE_OBJECT
            CREATE_SHARED_LIBRARY
            CREATE_PREPROCESSED_SOURCE
            CREATE_ASSEMBLY_SOURCE
            LINK_EXECUTABLE
        )
            string(REPLACE "${CMAKE_START_TEMP_FILE}" ""
                CMAKE_${lang}_${command} "${CMAKE_${lang}_${command}}"
            )
            string(REPLACE "${CMAKE_END_TEMP_FILE}" ""
                CMAKE_${lang}_${command} "${CMAKE_${lang}_${command}}"
            )
        endforeach()
    endforeach()
endif()

include(CTest)

if(NOT WIN32)
    message(FATAL_ERROR "The Windows targets must be configured on Windows.")
endif()

add_library(unlock_protocol_crypto STATIC
    Protocol/UnlockCrypto.cpp
    Protocol/SigningPayload.cpp
    Protocol/UnlockLogonBufferCodec.cpp
)

target_include_directories(unlock_protocol_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
)

target_compile_features(unlock_protocol_crypto PUBLIC cxx_std_20)
target_compile_definitions(unlock_protocol_crypto PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_protocol_crypto PUBLIC bcrypt advapi32)

add_library(unlock_service_ipc STATIC
    UnlockService/UnlockServiceIpc.cpp
)

target_include_directories(unlock_service_ipc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_service_ipc PUBLIC cxx_std_20)
target_compile_definitions(unlock_service_ipc PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_service_ipc PUBLIC advapi32)

add_library(unlock_enrollment_store STATIC
    UnlockService/EnrollmentStore.cpp
)

target_include_directories(unlock_enrollment_store
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_enrollment_store PUBLIC cxx_std_20)
target_compile_definitions(unlock_enrollment_store PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_enrollment_store PUBLIC advapi32 bcrypt crypt32)

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

    add_executable(unlock_service_ipc_tests
        UnlockServiceIpcTests/main.cpp
    )

    target_compile_features(unlock_service_ipc_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_service_ipc_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_service_ipc_tests PRIVATE unlock_service_ipc advapi32)

    add_test(NAME unlock_service_ipc_tests COMMAND unlock_service_ipc_tests)

    add_executable(unlock_enrollment_store_tests
        EnrollmentStoreTests/main.cpp
    )

    target_compile_features(unlock_enrollment_store_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_enrollment_store_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_enrollment_store_tests PRIVATE unlock_enrollment_store advapi32 bcrypt crypt32)

    add_test(NAME unlock_enrollment_store_tests COMMAND unlock_enrollment_store_tests)
endif()

add_executable(unlock_gatt_host
    GattHost/main.cpp
)

target_compile_features(unlock_gatt_host PRIVATE cxx_std_20)
target_compile_definitions(unlock_gatt_host PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_gatt_host PRIVATE unlock_service_ipc windowsapp bcrypt)

add_executable(unlock_service_host
    UnlockService/main.cpp
)

target_compile_features(unlock_service_host PRIVATE cxx_std_20)
target_compile_definitions(unlock_service_host PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_service_host PRIVATE unlock_service_core unlock_service_ipc unlock_enrollment_store windowsapp bcrypt advapi32 crypt32)

add_executable(unlock_pairing_tool
    PairingTool/main.cpp
)

target_compile_features(unlock_pairing_tool PRIVATE cxx_std_20)
target_compile_definitions(unlock_pairing_tool PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_pairing_tool PRIVATE unlock_enrollment_store unlock_service_ipc windowsapp shell32 ole32 propsys)

# UnlockService, CredentialProvider and LSAAuthenticationPackage remain
# intentionally separate targets. They will be added only when each target
# has an explicit installation and failure policy.
