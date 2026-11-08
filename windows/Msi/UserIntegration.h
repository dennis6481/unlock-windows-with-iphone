#pragma once
#include <Windows.h>
#include <functional>
#include <string>
namespace unlock::components {
std::wstring tokenSid(HANDLE token);
std::wstring processSid(HANDLE process);
void withUserHive(const std::wstring& sid, const std::function<void(HKEY)>& operation);
std::wstring consoleUserSid();
void registerUserStartup(const std::wstring& sid);
void removeUserStartup(const std::wstring& sid);
void stopTray(const std::wstring& sid);
bool mainInstancesPresent();
}
