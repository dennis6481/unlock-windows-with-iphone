# Created by Rui MA on 26 Sep 2026

CONFIG = Debug
BUILD_DIR = build
TMP_DIR = $(CURDIR)\..\.tmp
CMAKE = cmake
CTEST = ctest
VS_DEV_CMD = auto
CMAKE_GENERATOR = NMake Makefiles
TARGET_ARCH = auto
NATIVE_VSDEV_CMD = $(CURDIR)\Invoke-NativeVsDevCmd.cmd

all: build test

help:
	@echo "make                 configure, build and run all tests"
	@echo "make build           configure and build all Windows targets"
	@echo "make build-release   configure and build Release targets"
	@echo "make release         alias for make build-release"
	@echo "make test            build and run all CTest tests"
	@echo "make clean           remove CMake build outputs"
	@echo "make run-service     start the foreground UnlockService host"
	@echo "make run-gatt        start the foreground GATT host"
	@echo "make CONFIG=Release  use a different CMake configuration"
	@echo "make TARGET_ARCH=x64  override automatic native architecture detection"
	@echo "make TARGET_ARCH=arm64 override automatic native architecture detection"
	@echo "make VS_DEV_CMD=C:\path\to\VsDevCmd.bat override Visual Studio discovery"

configure:
	(if not exist "$(TMP_DIR)" mkdir "$(TMP_DIR)") && set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_CMAKE_COMMAND=$(CMAKE)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && call "$(NATIVE_VSDEV_CMD)" --fresh -S . -B "$(BUILD_DIR)" -G "$(CMAKE_GENERATOR)" -DCMAKE_BUILD_TYPE=$(CONFIG)

build: configure
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_CMAKE_COMMAND=$(CMAKE)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && call "$(NATIVE_VSDEV_CMD)" --build "$(BUILD_DIR)" --config $(CONFIG)

configure-release:
	(if not exist "$(TMP_DIR)" mkdir "$(TMP_DIR)") && set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_CMAKE_COMMAND=$(CMAKE)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && call "$(NATIVE_VSDEV_CMD)" --fresh -S . -B "$(BUILD_DIR)" -G "$(CMAKE_GENERATOR)" -DCMAKE_BUILD_TYPE=Release

build-release: configure-release
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_CMAKE_COMMAND=$(CMAKE)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && call "$(NATIVE_VSDEV_CMD)" --build "$(BUILD_DIR)" --config Release

release: build-release

test: build
	$(CTEST) --test-dir "$(BUILD_DIR)" -C $(CONFIG) --output-on-failure

clean:
	set "TEMP=$(TMP_DIR)" && set "TMP=$(TMP_DIR)" && set "UNLOCK_VS_DEV_CMD=$(VS_DEV_CMD)" && set "UNLOCK_CMAKE_COMMAND=$(CMAKE)" && set "UNLOCK_TARGET_ARCH=$(TARGET_ARCH)" && call "$(NATIVE_VSDEV_CMD)" --build "$(BUILD_DIR)" --target clean --config $(CONFIG)

run-service: build
	"$(BUILD_DIR)\unlock_service_host.exe"

run-gatt: build
	"$(BUILD_DIR)\unlock_gatt_host.exe"
