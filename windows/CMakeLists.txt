# Created by Rui MA on 26 Sep 2026

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
)

target_include_directories(unlock_protocol_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
)

target_compile_features(unlock_protocol_crypto PUBLIC cxx_std_20)
target_compile_definitions(unlock_protocol_crypto PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_protocol_crypto PUBLIC bcrypt)

add_library(unlock_saved_credential_ipc STATIC
    SavedCredential/SavedCredentialIpc.cpp
)
target_include_directories(unlock_saved_credential_ipc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/SavedCredential
)
target_compile_features(unlock_saved_credential_ipc PUBLIC cxx_std_20)
target_compile_definitions(unlock_saved_credential_ipc PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_saved_credential_ipc PUBLIC advapi32)

add_executable(unlock_saved_credential_service
    SavedCredential/SavedCredentialService.cpp
    SavedCredential/SavedCredentialVault.cpp
)
target_compile_features(unlock_saved_credential_service PRIVATE cxx_std_20)
target_compile_definitions(unlock_saved_credential_service PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)

add_executable(unlock_saved_credential_manager WIN32
    SavedCredential/SavedCredentialManager.cpp
)
target_compile_features(unlock_saved_credential_manager PRIVATE cxx_std_20)
target_compile_definitions(unlock_saved_credential_manager PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNLOCK_UI_SAVED_PASSWORD)
target_link_libraries(unlock_saved_credential_manager PRIVATE
    unlock_saved_credential_ipc advapi32 credui ole32 user32 comctl32 gdi32
)

if(BUILD_TESTING)
    add_executable(unlock_saved_credential_tests
        SavedCredentialTests/main.cpp
    )
    target_compile_features(unlock_saved_credential_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_saved_credential_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_saved_credential_tests PRIVATE unlock_saved_credential_ipc)
    add_test(NAME unlock_saved_credential_tests COMMAND unlock_saved_credential_tests)
endif()

add_library(unlock_enrollment_store STATIC
    PhoneApproval/EnrollmentStore.cpp
)

target_include_directories(unlock_enrollment_store
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/PhoneApproval
)

target_compile_features(unlock_enrollment_store PUBLIC cxx_std_20)
target_compile_definitions(unlock_enrollment_store PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_enrollment_store PUBLIC advapi32 bcrypt crypt32)

add_library(unlock_phone_approval_core STATIC
    PhoneApproval/PhoneApprovalCore.cpp
)

target_include_directories(unlock_phone_approval_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/Protocol
        ${CMAKE_CURRENT_SOURCE_DIR}/PhoneApproval
)

target_compile_features(unlock_phone_approval_core PUBLIC cxx_std_20)
target_compile_definitions(unlock_phone_approval_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_phone_approval_core PUBLIC unlock_protocol_crypto windowsapp bcrypt)

target_link_libraries(unlock_saved_credential_service PRIVATE
    unlock_saved_credential_ipc unlock_phone_approval_core unlock_enrollment_store
    advapi32 wtsapi32 crypt32 bcrypt windowsapp
)

if(BUILD_TESTING)
    add_executable(unlock_protocol_tests
        ProtocolTests/main.cpp
    )

    target_compile_features(unlock_protocol_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_protocol_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_protocol_tests PRIVATE unlock_protocol_crypto bcrypt)

    add_test(NAME unlock_protocol_tests COMMAND unlock_protocol_tests)

    add_executable(unlock_phone_approval_tests
        PhoneApprovalTests/main.cpp
    )

    target_compile_features(unlock_phone_approval_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_phone_approval_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_phone_approval_tests PRIVATE unlock_phone_approval_core unlock_protocol_crypto windowsapp bcrypt)

    add_test(NAME unlock_phone_approval_tests COMMAND unlock_phone_approval_tests)

    add_executable(unlock_enrollment_store_tests
        EnrollmentStoreTests/main.cpp
    )

    target_compile_features(unlock_enrollment_store_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_enrollment_store_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_enrollment_store_tests PRIVATE unlock_enrollment_store advapi32 bcrypt crypt32)

    add_test(NAME unlock_enrollment_store_tests COMMAND unlock_enrollment_store_tests)
endif()

add_executable(unlock_gatt_host WIN32
    GattHost/main.cpp
)

target_compile_features(unlock_gatt_host PRIVATE cxx_std_20)
target_compile_definitions(unlock_gatt_host PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_gatt_host PRIVATE unlock_saved_credential_ipc unlock_enrollment_store windowsapp user32 shell32 wtsapi32 ole32 advapi32 comctl32 gdi32)

if(MSVC)
    target_compile_options(unlock_gatt_host PRIVATE /utf-8)
endif()

add_executable(unlock_windows_components_wizard WIN32
    ComponentsWizard/main.cpp
    ComponentsWizard/ComponentState.cpp
    ComponentsWizard/ComponentTransaction.cpp
    ComponentsWizard/WindowsAdapter.cpp
    ComponentsWizard/DesktopDeployment.cpp
    ComponentsWizard/ComponentsWizard.rc
)

target_include_directories(unlock_windows_components_wizard
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ComponentsWizard
        ${CMAKE_CURRENT_SOURCE_DIR}/SavedCredential
)

target_compile_features(unlock_windows_components_wizard PRIVATE cxx_std_20)
set_target_properties(unlock_windows_components_wizard PROPERTIES OUTPUT_NAME setup)
target_compile_definitions(unlock_windows_components_wizard PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(
    unlock_windows_components_wizard
    PRIVATE
        advapi32
        comctl32
        gdi32
        ole32
        oleaut32
        secur32
        shell32
        taskschd
        uuid
        wtsapi32
        user32
        unlock_saved_credential_ipc
)

if(MSVC)
    target_link_options(unlock_windows_components_wizard PRIVATE /MANIFEST:NO)
endif()

if(BUILD_TESTING)
    add_executable(unlock_components_wizard_tests
        ComponentsWizardTests/main.cpp
        ComponentsWizard/ComponentState.cpp
    )

    target_include_directories(unlock_components_wizard_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ComponentsWizard
    )

    target_compile_features(unlock_components_wizard_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_components_wizard_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    add_test(NAME unlock_components_wizard_tests COMMAND unlock_components_wizard_tests)
endif()

add_executable(unlock_pairing_tool
    PairingTool/main.cpp
)

target_compile_features(unlock_pairing_tool PRIVATE cxx_std_20)
target_compile_definitions(unlock_pairing_tool PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNLOCK_UI_PAIRING)
target_link_libraries(unlock_pairing_tool PRIVATE unlock_enrollment_store unlock_saved_credential_ipc user32 wtsapi32 comctl32 gdi32)

add_library(unlock_credential_provider SHARED
    CredentialProvider/UnlockCredentialProvider.cpp
)

target_include_directories(unlock_credential_provider
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/CredentialProvider
        ${CMAKE_CURRENT_SOURCE_DIR}/SavedCredential
)

target_compile_features(unlock_credential_provider PRIVATE cxx_std_20)
target_compile_definitions(unlock_credential_provider PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(unlock_credential_provider PRIVATE unlock_saved_credential_ipc ole32 secur32 gdi32 credui wtsapi32 advapi32 user32)
if(MSVC)
    target_link_options(unlock_credential_provider PRIVATE
        /EXPORT:DllGetClassObject
        /EXPORT:DllCanUnloadNow
    )
endif()

if(BUILD_TESTING)
    add_executable(unlock_credential_provider_tests
        CredentialProviderTests/main.cpp
    )

    target_include_directories(unlock_credential_provider_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/CredentialProvider
    )

    target_compile_features(unlock_credential_provider_tests PRIVATE cxx_std_20)
    target_compile_definitions(unlock_credential_provider_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(unlock_credential_provider_tests PRIVATE ole32)

    add_test(NAME unlock_credential_provider_tests COMMAND unlock_credential_provider_tests)
endif()

set(UNLOCK_APP_ICON_ASSET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ios/Assets.xcassets/AppIcon.appiconset")
file(READ "${UNLOCK_APP_ICON_ASSET_DIR}/Contents.json" unlock_icon_manifest)
string(JSON unlock_icon_count LENGTH "${unlock_icon_manifest}" images)
math(EXPR unlock_icon_last "${unlock_icon_count} - 1")
set(UNLOCK_APP_ICON_SOURCE "")
foreach(unlock_icon_index RANGE ${unlock_icon_last})
    string(JSON unlock_icon_appearance ERROR_VARIABLE unlock_icon_error TYPE "${unlock_icon_manifest}" images ${unlock_icon_index} appearances)
    if(unlock_icon_error)
        if(UNLOCK_APP_ICON_SOURCE)
            message(FATAL_ERROR "AppIcon asset must have exactly one standard image")
        endif()
        string(JSON unlock_icon_filename GET "${unlock_icon_manifest}" images ${unlock_icon_index} filename)
        set(UNLOCK_APP_ICON_SOURCE "${UNLOCK_APP_ICON_ASSET_DIR}/${unlock_icon_filename}")
    endif()
endforeach()
if(NOT EXISTS "${UNLOCK_APP_ICON_SOURCE}")
    message(FATAL_ERROR "Standard iOS AppIcon source is missing")
endif()
configure_file(Resources/AppIcon.rc.in AppIcon.rc @ONLY)
configure_file(Resources/DesktopUi.rc.in DesktopUi.rc @ONLY)
foreach(unlock_desktop_target IN ITEMS unlock_gatt_host unlock_pairing_tool unlock_saved_credential_manager)
    target_sources(${unlock_desktop_target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/DesktopUi.rc)
    if(MSVC)
        target_link_options(${unlock_desktop_target} PRIVATE /MANIFEST:NO)
    endif()
endforeach()
target_sources(unlock_credential_provider PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/AppIcon.rc)
get_property(unlock_windows_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(unlock_windows_target IN LISTS unlock_windows_targets)
    get_target_property(unlock_windows_target_type ${unlock_windows_target} TYPE)
    if(unlock_windows_target_type STREQUAL "EXECUTABLE")
        target_sources(${unlock_windows_target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/AppIcon.rc)
    endif()
endforeach()
