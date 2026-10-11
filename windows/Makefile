# Created by Rui MA on 26 Sep 2026

CONFIG = Debug
BUILD_DIR = build
TMP_DIR = $(CURDIR)\..\.tmp
VS_DEV_CMD = auto
TARGET_ARCH = auto
BUILD_TESTING = ON
WINDOWS_BUILD_SCRIPT = $(CURDIR)\WindowsBuild.ps1
SOLUTION = $(CURDIR)\UnlockWindows.sln
TEST_PROJECT = $(CURDIR)\UnlockWindowsTests.proj
ABS_BUILD_DIR = $(abspath $(BUILD_DIR))

unexport MAKEFLAGS

all: build test

help:
	@echo "make                 configure, build and run all tests"
	@echo "make build           configure and build the Windows Solution"
	@echo "make build-release   configure and build Release targets"
	@echo "make release         alias for make build-release"
	@echo "make test            build and run the MSBuild test project"
	@echo "make clean           run MSBuild Clean and remove generated resources"
	@echo "make run-app         build and start Unlock with iPhone"
	@echo "make CONFIG=Release  use a different MSBuild configuration"
	@echo "make TARGET_ARCH=x64  override automatic native architecture detection"
	@echo "make TARGET_ARCH=arm64 override automatic native architecture detection"
	@echo "make VS_DEV_CMD=C:\path\to\VsDevCmd.bat override Visual Studio discovery"
	@echo "make BUILD_TESTING=OFF skip test projects during the solution build"

configure:
	(if not exist "$(TMP_DIR)" mkdir "$(TMP_DIR)") && set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(WINDOWS_BUILD_SCRIPT)" -Prepare -OutputDirectory "$(BUILD_DIR)"
	if not exist "$(SOLUTION)" (echo Missing MSBuild solution: $(SOLUTION) 1>&2 && exit /b 2)

build: configure
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(WINDOWS_BUILD_SCRIPT)" -InvokeMSBuild "$(SOLUTION)" /restore /m /nologo "/p:Configuration=$(CONFIG)" "/p:UnlockBuildDirectory=$(ABS_BUILD_DIR)" "/p:BuildTesting=$(BUILD_TESTING)"

configure-release:
	$(MAKE) CONFIG=Release BUILD_DIR="$(BUILD_DIR)" TARGET_ARCH=$(TARGET_ARCH) VS_DEV_CMD="$(VS_DEV_CMD)" BUILD_TESTING=$(BUILD_TESTING) configure

build-release: configure-release
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(WINDOWS_BUILD_SCRIPT)" -InvokeMSBuild "$(SOLUTION)" /restore /m /nologo "/p:Configuration=Release" "/p:UnlockBuildDirectory=$(ABS_BUILD_DIR)" "/p:BuildTesting=$(BUILD_TESTING)"

release: build-release

test: build
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(WINDOWS_BUILD_SCRIPT)" -InvokeMSBuild "$(TEST_PROJECT)" /t:Test /m:1 /nologo "/p:Configuration=$(CONFIG)" "/p:UnlockBuildDirectory=$(ABS_BUILD_DIR)"

clean:
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(WINDOWS_BUILD_SCRIPT)" -InvokeMSBuild "$(SOLUTION)" /t:Clean /m /nologo "/p:Configuration=$(CONFIG)" "/p:UnlockBuildDirectory=$(ABS_BUILD_DIR)"
	if exist "$(BUILD_DIR)\generated" rmdir /s /q "$(BUILD_DIR)\generated"
	if exist "$(BUILD_DIR)\package" rmdir /s /q "$(BUILD_DIR)\package"

run-app: build
	"$(BUILD_DIR)\UnlockWithIPhone.exe"
