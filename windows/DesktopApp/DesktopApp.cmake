# Created by Rui MA on 09 Oct 2026

find_program(UNLOCK_DESKTOP_MSBUILD NAMES MSBuild.exe MSBuild
    HINTS "$ENV{VSINSTALLDIR}/MSBuild/Current/Bin" REQUIRED)

set(UNLOCK_DESKTOP_PLATFORM "${UNLOCK_SETUP_ARCHITECTURE}")
if(UNLOCK_DESKTOP_PLATFORM STREQUAL "arm64")
    set(UNLOCK_DESKTOP_PLATFORM ARM64)
endif()
set(UNLOCK_DESKTOP_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
get_target_property(unlock_desktop_standard unlock_desktop_native CXX_STANDARD)
set(UNLOCK_DESKTOP_CPP_STANDARD "stdcpp${unlock_desktop_standard}")
set(UNLOCK_DESKTOP_OPTIONS "$<JOIN:$<TARGET_PROPERTY:unlock_desktop_native,COMPILE_OPTIONS>, >")
set(UNLOCK_DESKTOP_DEFINITIONS "UNICODE;_UNICODE;$<JOIN:$<TARGET_PROPERTY:unlock_desktop_native,COMPILE_DEFINITIONS>,;>")
set(UNLOCK_DESKTOP_INCLUDES "$<JOIN:$<TARGET_PROPERTY:unlock_desktop_native,INCLUDE_DIRECTORIES>,;>")
string(REGEX MATCH "kMinimumWindowsBuild = ([0-9]+);" unlock_minimum_windows_match "${unlock_component_manifest}")
if(NOT unlock_minimum_windows_match)
    message(FATAL_ERROR "Missing minimum Windows build in ComponentFiles.h")
endif()
set(UNLOCK_MINIMUM_WINDOWS_BUILD "${CMAKE_MATCH_1}")
set(unlock_desktop_libraries "$<TARGET_FILE:unlock_desktop_native>")
set(UNLOCK_DESKTOP_SDK "$ENV{WindowsSDKVersion}")
string(REGEX REPLACE "[/\\]+$" "" UNLOCK_DESKTOP_SDK "${UNLOCK_DESKTOP_SDK}")
if(NOT UNLOCK_DESKTOP_SDK MATCHES "^10\\.0\\.[0-9]+\\.0$" OR UNLOCK_DESKTOP_SDK VERSION_LESS "10.0.22621.0")
    message(FATAL_ERROR "Run from a Visual Studio developer environment with Windows SDK 10.0.22621.0 or newer; WindowsSDKVersion=${UNLOCK_DESKTOP_SDK}")
endif()
get_target_property(unlock_desktop_dependencies unlock_desktop_native LINK_LIBRARIES)
foreach(unlock_desktop_dependency IN LISTS unlock_desktop_dependencies)
    if(TARGET ${unlock_desktop_dependency})
        list(APPEND unlock_desktop_libraries "$<TARGET_FILE:${unlock_desktop_dependency}>")
    else()
        list(APPEND unlock_desktop_libraries "${unlock_desktop_dependency}.lib")
    endif()
endforeach()
string(JOIN ";" UNLOCK_DESKTOP_LIBRARIES ${unlock_desktop_libraries})
set(unlock_desktop_project "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp/$<CONFIG>/DesktopApp.vcxproj")
configure_file("${CMAKE_CURRENT_LIST_DIR}/DesktopApp.vcxproj.in"
    "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp/DesktopApp.vcxproj.in" @ONLY)
file(GENERATE OUTPUT "${unlock_desktop_project}"
    INPUT "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp/DesktopApp.vcxproj.in" TARGET unlock_desktop_native)

add_custom_target(unlock_desktop_app ALL
    COMMAND "${UNLOCK_DESKTOP_MSBUILD}" "${unlock_desktop_project}"
        /restore /m /nologo /verbosity:minimal "/p:Configuration=$<CONFIG>" "/p:Platform=${UNLOCK_DESKTOP_PLATFORM}"
    BYPRODUCTS "${UNLOCK_DESKTOP_OUTPUT}" "${CMAKE_CURRENT_BINARY_DIR}/DesktopApp.files"
    VERBATIM USES_TERMINAL)
add_dependencies(unlock_desktop_app unlock_desktop_native)
