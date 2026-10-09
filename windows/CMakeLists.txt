# Created by Rui MA on 26 Sep 2026

cmake_minimum_required(VERSION 3.25)

project(UnlockWindowsWithIPhone LANGUAGES CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

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
target_link_libraries(unlock_enrollment_store PUBLIC unlock_protocol_crypto advapi32 bcrypt crypt32)

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
    advapi32 wtsapi32 crypt32 bcrypt windowsapp ole32
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

add_library(unlock_desktop_native STATIC
    DesktopApp/TrayManager.cpp
    GattHost/GattHost.cpp
    Enrollment/Enrollment.cpp
)

set_target_properties(unlock_desktop_native PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)
target_compile_definitions(unlock_desktop_native PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNLOCK_UI_PAIRING)
target_link_libraries(unlock_desktop_native PRIVATE
    unlock_saved_credential_ipc unlock_enrollment_store unlock_protocol_crypto
    windowsapp user32 shell32 wtsapi32 ole32 advapi32 comctl32 gdi32 bcrypt crypt32)

if(MSVC)
    target_compile_options(unlock_desktop_native PRIVATE /utf-8)
endif()

add_library(unlock_windows_components_wizard_objects OBJECT
    ComponentsWizard/main.cpp
    ComponentsWizard/ComponentState.cpp
    ComponentsWizard/ComponentTransaction.cpp
    ComponentsWizard/WindowsAdapter.cpp
    ComponentsWizard/PackageManifest.cpp
    ComponentsWizard/DesktopDeployment.cpp
    ComponentsWizard/SetupFinalization.cpp
    ComponentsWizard/ComponentsWizard.rc
)

add_executable(unlock_windows_components_wizard WIN32 $<TARGET_OBJECTS:unlock_windows_components_wizard_objects>)

target_include_directories(unlock_windows_components_wizard_objects
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ComponentsWizard
        ${CMAKE_CURRENT_SOURCE_DIR}/SavedCredential
)

target_compile_features(unlock_windows_components_wizard_objects PRIVATE cxx_std_20)

target_compile_definitions(unlock_windows_components_wizard_objects PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
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
        version
        unlock_saved_credential_ipc
        unlock_protocol_crypto
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

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/ComponentFiles.h" unlock_component_manifest)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/ProductVersion.h" unlock_product_version)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ProductVersion.h")
string(REGEX MATCH "kProductVersion\\{([0-9]+), ([0-9]+), ([0-9]+)\\}" unlock_version_match "${unlock_product_version}")
if(NOT unlock_version_match)
    message(FATAL_ERROR "Missing Windows product version")
endif()
set(UNLOCK_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(UNLOCK_VERSION_MINOR "${CMAKE_MATCH_2}")
set(UNLOCK_VERSION_PATCH "${CMAKE_MATCH_3}")
set(UNLOCK_VERSION_TEXT "${UNLOCK_VERSION_MAJOR}.${UNLOCK_VERSION_MINOR}.${UNLOCK_VERSION_PATCH}")
string(TOLOWER "${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" UNLOCK_SETUP_ARCHITECTURE)
if(NOT UNLOCK_SETUP_ARCHITECTURE MATCHES "^(x64|arm64)$")
    message(FATAL_ERROR "Unsupported Windows target architecture: ${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}. Only x64 and ARM64 are supported.")
endif()
set(UNLOCK_SETUP_OUTPUT_NAME "UnlockWithIPhone_${UNLOCK_VERSION_TEXT}_${UNLOCK_SETUP_ARCHITECTURE}_setup")
set(UNLOCK_DIST_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/dist")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ComponentFiles.h")
set(unlock_payload_targets "")
set(unlock_payload_files "")
foreach(unlock_component IN ITEMS
    "unlock_credential_provider|kCredentialProviderFile"
    "unlock_saved_credential_service|kSavedCredentialServiceFile"
    "unlock_desktop_native|kMainAppFile"
    "unlock_windows_components_wizard|kInstallerFile"
)
    string(REPLACE "|" ";" unlock_component_parts "${unlock_component}")
    list(GET unlock_component_parts 0 unlock_component_target)
    list(GET unlock_component_parts 1 unlock_component_key)
    string(REGEX MATCH "${unlock_component_key}\\[\\] = L\"([^\"]+)\";" unlock_component_match "${unlock_component_manifest}")
    if(NOT unlock_component_match)
        message(FATAL_ERROR "Missing shared component filename: ${unlock_component_key}")
    endif()
    set(UNLOCK_VERSION_FILENAME "${CMAKE_MATCH_1}")
    get_filename_component(unlock_component_output "${UNLOCK_VERSION_FILENAME}" NAME_WE)
    if(unlock_component_target STREQUAL "unlock_windows_components_wizard")
        set(unlock_component_output "${UNLOCK_SETUP_OUTPUT_NAME}")
        set(UNLOCK_VERSION_FILENAME "${UNLOCK_SETUP_OUTPUT_NAME}.exe")
        set_target_properties(${unlock_component_target} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "$<1:${UNLOCK_DIST_DIRECTORY}>"
            PDB_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
        if(MSVC)
            target_link_options(${unlock_component_target} PRIVATE
                "$<$<CONFIG:Debug>:/ILK:${CMAKE_CURRENT_BINARY_DIR}/${UNLOCK_SETUP_OUTPUT_NAME}.ilk>")
        endif()
    else()
        if(unlock_component_target STREQUAL "unlock_desktop_native")
            set(UNLOCK_DESKTOP_NAME "${unlock_component_output}")
            set(UNLOCK_DESKTOP_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${UNLOCK_VERSION_FILENAME}")
            list(APPEND unlock_payload_targets unlock_desktop_app)
            list(APPEND unlock_payload_files "${UNLOCK_DESKTOP_OUTPUT}")
        else()
            list(APPEND unlock_payload_targets "${unlock_component_target}")
            list(APPEND unlock_payload_files "$<TARGET_FILE:${unlock_component_target}>")
        endif()
    endif()
    if(NOT unlock_component_target STREQUAL "unlock_desktop_native")
        set_target_properties(${unlock_component_target} PROPERTIES OUTPUT_NAME "${unlock_component_output}")
    endif()
    if(unlock_component_target STREQUAL "unlock_credential_provider")
        set(UNLOCK_VERSION_FILE_TYPE "VFT_DLL")
    else()
        set(UNLOCK_VERSION_FILE_TYPE "VFT_APP")
    endif()
    configure_file(Resources/ProductVersion.rc.in "${unlock_component_target}-version.rc" @ONLY)
    if(unlock_component_target STREQUAL "unlock_desktop_native")
        set(UNLOCK_DESKTOP_VERSION_RESOURCE "${CMAKE_CURRENT_BINARY_DIR}/${unlock_component_target}-version.rc")
    elseif(unlock_component_target STREQUAL "unlock_windows_components_wizard")
        target_sources(unlock_windows_components_wizard_objects PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/${unlock_component_target}-version.rc")
    else()
        target_sources(${unlock_component_target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/${unlock_component_target}-version.rc")
    endif()
endforeach()

find_program(UNLOCK_POWERSHELL powershell REQUIRED)
set(unlock_payload_directory "${CMAKE_CURRENT_BINARY_DIR}/package/$<CONFIG>")
add_custom_command(
    OUTPUT "${unlock_payload_directory}/PackagePayload.rc" "${unlock_payload_directory}/PackagePayload.bin"
    COMMAND "${UNLOCK_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
        -File "${CMAKE_CURRENT_SOURCE_DIR}/WindowsArchitecture.ps1"
        "${UNLOCK_VERSION_TEXT}" "${unlock_payload_directory}/PackagePayload.rc"
        "${unlock_payload_directory}/PackagePayload.bin" "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp.files" ${unlock_payload_files}
    DEPENDS ${unlock_payload_targets} ${unlock_payload_files}
        "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp.files"
        "${CMAKE_CURRENT_SOURCE_DIR}/WindowsArchitecture.ps1"
        "${CMAKE_CURRENT_SOURCE_DIR}/ProductVersion.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/ComponentFiles.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/ComponentsWizard/PackageManifest.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/Protocol/UnlockCrypto.h"
    VERBATIM
)
target_sources(unlock_windows_components_wizard PRIVATE
    "${unlock_payload_directory}/PackagePayload.rc")
target_include_directories(unlock_windows_components_wizard PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
add_dependencies(unlock_windows_components_wizard ${unlock_payload_targets})

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
target_sources(unlock_credential_provider PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/AppIcon.rc)
target_sources(unlock_windows_components_wizard_objects PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/AppIcon.rc)
get_property(unlock_windows_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
foreach(unlock_windows_target IN LISTS unlock_windows_targets)
    get_target_property(unlock_windows_target_type ${unlock_windows_target} TYPE)
    if(unlock_windows_target_type STREQUAL "EXECUTABLE" AND NOT unlock_windows_target STREQUAL "unlock_windows_components_wizard")
        target_sources(${unlock_windows_target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/AppIcon.rc)
    endif()
endforeach()

include(DesktopApp/DesktopApp.cmake)
