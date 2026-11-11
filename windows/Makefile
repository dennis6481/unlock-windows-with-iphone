# Created by Rui MA on 26 Sep 2026

SHELL = cmd.exe
TARGET_ARCH = auto
SOLUTION = $(CURDIR)\UnlockWindows.sln
NATIVE_ARCH = $(if $(PROCESSOR_ARCHITEW6432),$(PROCESSOR_ARCHITEW6432),$(PROCESSOR_ARCHITECTURE))
SELECTED_ARCH = $(if $(filter auto,$(TARGET_ARCH)),$(if $(filter AMD64,$(NATIVE_ARCH)),x64,$(if $(filter ARM64 ARM64EC,$(NATIVE_ARCH)),arm64,unsupported)),$(TARGET_ARCH))
VS_COMPONENT = $(if $(filter arm64,$(SELECTED_ARCH)),Microsoft.VisualStudio.Component.VC.Tools.ARM64,Microsoft.VisualStudio.Component.VC.Tools.x86.x64)
ifeq ($(strip $(MSBUILD)),)
VS_INSTALL := $(shell "${ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -prerelease -products * -requires Microsoft.Component.MSBuild $(VS_COMPONENT) -property installationPath)
override MSBUILD := $(VS_INSTALL)\MSBuild\Current\Bin\MSBuild.exe
endif
BUILD_ARGUMENTS = /nologo /p:Platform=$(SELECTED_ARCH) $(if $(CONFIG),/p:Configuration=$(CONFIG)) $(if $(BUILD_DIR),"/p:UnlockBuildDirectory=$(BUILD_DIR)") $(if $(BUILD_TESTING),/p:BuildTesting=$(BUILD_TESTING))

unexport MAKEFLAGS

all: test

.PHONY: all help check-msbuild build build-release release test clean run-app

help:
	@echo make build / build-release / test / clean / run-app
	@echo make defaults to building and running all tests
	@echo CONFIG=Release TARGET_ARCH=auto/x64/arm64 BUILD_DIR=path BUILD_TESTING=ON/OFF
	@echo MSBUILD=C:\path\to\MSBuild.exe overrides Visual Studio discovery

check-msbuild:
	@if "$(SELECTED_ARCH)"=="unsupported" (echo Unsupported native Windows architecture. Use x64 or arm64. 1>&2 && exit /b 2)
	@if not exist "$(MSBUILD)" (echo MSBuild with the target C++ tools was not found. Install Visual Studio or set MSBUILD. 1>&2 && exit /b 2)

build: check-msbuild
	"$(MSBUILD)" "$(SOLUTION)" /restore /m $(BUILD_ARGUMENTS)

build-release: check-msbuild
	"$(MSBUILD)" "$(SOLUTION)" /restore /m $(BUILD_ARGUMENTS) /p:Configuration=Release

release: build-release

test: check-msbuild
	"$(MSBUILD)" "$(SOLUTION)" /restore /m $(BUILD_ARGUMENTS) /p:RunTests=true

clean: check-msbuild
	"$(MSBUILD)" "$(SOLUTION)" /t:Clean /m $(BUILD_ARGUMENTS)

run-app: build
	"$(MSBUILD)" "$(SOLUTION)" /t:RunApp $(BUILD_ARGUMENTS)
