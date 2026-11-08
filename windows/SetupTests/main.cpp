#include "../Msi/ActionPolicy.h"
#include "../Msi/LegacySchema5.h"
#include "../DesktopApp/DesktopApp.h"
#include <cstdlib>
#include <iostream>
#include <initializer_list>
#include <vector>
using namespace unlock::components;
void expect(bool condition, const char* message) {
    if (!condition) { std::cerr << "FAILED: " << message << '\n'; std::exit(EXIT_FAILURE); }
}
int main() {
    using unlock_windows::desktop_app::Role;
    const auto launch = [](std::initializer_list<const wchar_t*> values) {
        std::vector<wchar_t*> arguments;
        for (const auto* value : values) arguments.push_back(const_cast<wchar_t*>(value));
        return unlock_windows::desktop_app::parseLaunch(static_cast<int>(arguments.size()), arguments.data());
    };
    expect(launch({L"app"}).role == Role::tray, "ordinary startup selects only the tray role");
    const auto restored = launch({L"app", L"--restore-tray"});
    expect(restored.role == Role::tray && restored.background && restored.suppressSetupPrompt,
        "maintenance restores the tray without consuming or showing the first setup prompt");
    expect(launch({L"app", L"--saved-password"}).role == Role::savedPassword,
        "password management does not select the tray role");
    expect(launch({L"app", L"--binding-helper", L"21", L"00"}).role == Role::bindingHelper, "UAC helper dispatch remains separate");
    for (const auto arguments : {
            std::initializer_list<const wchar_t*>{L"app", L"--saved-password", L"--clear"},
            {L"app", L"--bind"}, {L"app", L"--bind", L"--remove"}, {L"app", L"--key-hex"}, {L"app", L"--key-clipboard", L"--saved-password"},
            {L"app", L"--clear", L"--replace"}, {L"app", L"--bluetooth"}, {L"app", L"--unknown"}}) {
        bool rejected = false;
        try { launch(arguments); } catch (const std::invalid_argument&) { rejected = true; }
        expect(rejected, "unknown, incomplete or conflicting roles are rejected before dispatch");
    }
    expect(parseProductVersion(kProductVersion.text()) == kProductVersion, "configured product version round trip");
    expect(parseProductVersion(L"1.2.3") == ProductVersion{1, 2, 3, 0}, "public release versions default build to zero");
    expect(parseProductVersion(L"1.2.3.42") == ProductVersion{1, 2, 3, 42}, "four-part product version round trip");
    expect(parseProductVersion(L"65535.65535.65535.65535") == ProductVersion{65535, 65535, 65535, 65535}, "all version parts support the resource limit");
    expect(packageAction({0, 10, 0, 0}, {0, 9, 9, 65535}) == PackageAction::update, "numeric minor version comparison");
    expect(packageAction({1, 0, 0, 0}, {0, 65535, 65535, 65535}) == PackageAction::update, "major version takes precedence");
    expect(packageAction({1, 2, 3, 10}, {1, 2, 3, 9}) == PackageAction::update, "build comparison is numeric");
    expect(packageAction({1, 2, 4, 0}, {1, 2, 3, 65535}) == PackageAction::update, "patch takes precedence over build");
    expect(packageAction({1, 2, 3, 9}, {1, 2, 3, 10}) == PackageAction::rejectDowngrade, "lower builds are rejected");
    expect(ProductVersion{1, 2, 3, 42}.release() == ProductVersion{1, 2, 3, 0}.release(), "public releases ignore build differences");
    expect(ProductVersion{1, 2, 4, 0}.release() > ProductVersion{1, 2, 3, 65535}.release(), "public updates compare release versions");
    expect(packageAction(kProductVersion, kProductVersion) == PackageAction::reinstall, "same version requires explicit reinstall");
    expect(packageAction({0, 1, 0, 0}, {0, 1, 1, 0}) == PackageAction::rejectDowngrade, "reject downgrade");
    for (const auto* invalid : {L"", L"0.1", L"0.1.0.", L"1.2.3.4.5", L"01.1.0", L"1.2.3.04", L"1.-1.0",
            L"65536.0.0", L"1.2.3.65536", L"999999999999999999999.0.0", L"0.1.0junk", L"1.2.3.4junk"})
        expect(!parseProductVersion(invalid), "malformed product versions fail closed");
    using namespace unlock::components::msi;
    expect(supportedLegacyVersion(5,L"1.0.0.23") == ProductVersion{1,0,0,23}, "complete schema 5 version can be read");
    expect(!supportedLegacyVersion(4,L"1.0.0.23"), "earlier schemas are rejected");
    expect(!supportedLegacyVersion(0,L"1.0.0.23"), "missing schema is rejected");
    expect(!supportedLegacyVersion(5,L"1.0.0"), "legacy takeover requires the fourth version part");
    expect(!supportedLegacyVersion(5,L"1.0.0.023"), "noncanonical legacy version is rejected");
    expect(packageAction({1,0,0,24},{1,0,0,23}) == PackageAction::update, "fourth part update");
    expect(packageAction({1,0,0,24},{1,0,0,24}) == PackageAction::reinstall, "fourth part reinstall");
    expect(packageAction({1,0,0,23},{1,0,0,24}) == PackageAction::rejectDowngrade, "fourth part downgrade");
    expect(operation(false,false,false,false) == Operation::firstInstall, "fresh install");
    expect(operation(false,false,false,true) == Operation::maintain, "migration and major upgrade preserve configuration");
    expect(operation(true,false,false,true) == Operation::maintain, "repair preserves configuration");
    expect(operation(true,true,true,true) == Operation::upgradeRemoval, "upgrade removal preserves credentials");
    expect(operation(true,true,false,true) == Operation::remove, "active removal clears credentials");
    using IpcOperation = unlock_windows::saved_credential::Operation;
    expect(maintenanceAllowed(true,true,IpcOperation::clearForRemoval), "native SYSTEM MSI may clear for removal");
    expect(!maintenanceAllowed(false,true,IpcOperation::clearForRemoval), "ordinary user cannot use maintenance identity");
    expect(!maintenanceAllowed(true,false,IpcOperation::clearForRemoval), "other SYSTEM processes cannot use maintenance identity");
    for (unsigned code=0; code<65536; ++code) {
        const auto value = static_cast<IpcOperation>(code);
        if (value != IpcOperation::clearForRemoval)
            expect(!maintenanceAllowed(true,true,value), "maintenance identity cannot invoke other operations");
    }
    for (const auto name : {L"runtime.dll",L"nested\\runtime.dll"})
        expect(isPackageRelativePath(name), "legacy manifest accepts relative dependency names");
    for (const auto name : {L"",L"..\\file",L"C:\\file",L"\\file",L"a\\..\\b",L"a:stream",L"NUL",L"file. ",L"a\\CON.dll"})
        expect(!isPackageRelativePath(name), "unsafe legacy dependency paths rejected before adoption");
    return EXIT_SUCCESS;
}
