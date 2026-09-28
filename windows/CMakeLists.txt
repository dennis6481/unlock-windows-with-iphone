# Modified by Rui MA on 26 Sep 2026
# Modified by Rui MA on 26 Sep 2026

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

add_library(unlock_lsa_verifier STATIC
    LSAAuthenticationPackage/UnlockLsaLogonVerifier.cpp
)

target_include_directories(unlock_lsa_verifier
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/LSAAuthenticationPackage
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_lsa_verifier PUBLIC cxx_std_20)
target_compile_definitions(unlock_lsa_verifier PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(
    unlock_lsa_verifier
    PUBLIC
        unlock_protocol_crypto
        unlock_enrollment_store
        advapi32
        bcrypt
        crypt32
)

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

add_library(unlock_lsa_authentication_package SHARED
    LSAAuthenticationPackage/UnlockLsaAuthenticationPackage.cpp
)

target_include_directories(unlock_lsa_authentication_package
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/LSAAuthenticationPackage
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_lsa_authentication_package PRIVATE cxx_std_20)
target_compile_definitions(unlock_lsa_authentication_package PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_lsa_authentication_package PRIVATE unlock_lsa_verifier advapi32)
if(MSVC)
    target_link_options(unlock_lsa_authentication_package PRIVATE
        /EXPORT:LsaApInitializePackage
        /EXPORT:LsaApLogonUserEx2
        /EXPORT:LsaApCallPackage
        /EXPORT:LsaApCallPackageUntrusted
        /EXPORT:LsaApCallPackagePassthrough
        /EXPORT:LsaApLogonTerminated
    )
endif()

add_executable(unlock_lsa_package_lookup
    LSAAuthenticationPackage/LookupAuthenticationPackage.cpp
)

target_include_directories(unlock_lsa_package_lookup
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
)

target_compile_features(unlock_lsa_package_lookup PRIVATE cxx_std_20)
target_compile_definitions(unlock_lsa_package_lookup PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_lsa_package_lookup PRIVATE secur32)

add_executable(unlock_windows_components_wizard WIN32
    ComponentsWizard/main.cpp
)

target_compile_features(unlock_windows_components_wizard PRIVATE cxx_std_20)
target_compile_definitions(unlock_windows_components_wizard PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(
    unlock_windows_components_wizard
    PRIVATE
        advapi32
        comctl32
        ole32
        oleaut32
        secur32
        shell32
        taskschd
        user32
)

add_executable(unlock_pairing_tool
    PairingTool/main.cpp
)

target_compile_features(unlock_pairing_tool PRIVATE cxx_std_20)
target_compile_definitions(unlock_pairing_tool PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_pairing_tool PRIVATE unlock_enrollment_store unlock_service_ipc windowsapp shell32 ole32 propsys)

add_library(unlock_credential_provider SHARED
    CredentialProvider/UnlockCredentialProvider.cpp
    CredentialProvider/UnlockCredentialApprovalClient.cpp
    CredentialProvider/UnlockCredentialSerialization.cpp
)

target_include_directories(unlock_credential_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/CredentialProvider
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
)

target_compile_features(unlock_credential_provider PRIVATE cxx_std_20)
target_compile_definitions(unlock_credential_provider PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_credential_provider PRIVATE unlock_protocol_crypto unlock_service_ipc ole32 secur32 gdi32)
if(MSVC)
    target_link_options(unlock_credential_provider PRIVATE
        /EXPORT:DllGetClassObject
        /EXPORT:DllCanUnloadNow
    )
endif()

if(BUILD_TESTING)
    add_executable(unlock_credential_provider_tests
        CredentialProviderTests/main.cpp
        CredentialProvider/UnlockCredentialSerialization.cpp
    )

    target_include_directories(unlock_credential_provider_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/CredentialProvider
            ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
    )

    target_compile_features(unlock_credential_provider_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_credential_provider_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_credential_provider_tests PRIVATE unlock_protocol_crypto ole32)

    add_test(NAME unlock_credential_provider_tests COMMAND unlock_credential_provider_tests)

    add_executable(unlock_lsa_authentication_package_tests
        LSAAuthenticationPackageTests/main.cpp
    )

    target_include_directories(unlock_lsa_authentication_package_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/LSAAuthenticationPackage
            ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
            ${CMAKE_CURRENT_SOURCE_DIR}/UnlockService
    )

    target_compile_features(unlock_lsa_authentication_package_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_lsa_authentication_package_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(
        unlock_lsa_authentication_package_tests
        PRIVATE
            unlock_lsa_verifier
            unlock_protocol_crypto
            unlock_enrollment_store
            advapi32
            bcrypt
            crypt32
    )
    add_dependencies(
        unlock_lsa_authentication_package_tests
        unlock_lsa_authentication_package
    )

    add_test(
        NAME unlock_lsa_authentication_package_tests
        COMMAND unlock_lsa_authentication_package_tests
    )
endif()

# The CredentialProvider and LSAAuthenticationPackage targets are build-only
# prototypes. UnlockService, CredentialProvider and LSAAuthenticationPackage
# remain separate targets so each can acquire an explicit installation and
# failure policy independently.
