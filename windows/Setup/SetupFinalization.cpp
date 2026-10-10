// Created by Rui MA on 04 Oct 2026

#define UNICODE
#define _UNICODE
#include "SetupFinalization.h"
#include "../DesktopApp/DesktopApp.h"
#include "SetupPlatform.h"
#include <taskschd.h>
#include <wrl/client.h>
#include "../SavedCredential/SavedCredentialVault.h"
#include <Windows.h>
#include <array>
#include <map>

namespace unlock::components {
// Task scheduling and generated scripts share the same transaction/result contract.
namespace {
using Microsoft::WRL::ComPtr;
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& s) : value(SysAllocString(s.c_str())) {
        if (!value) throw ComponentError(L"Out of memory allocating task text.");
    }
    ~Bstr() { SysFreeString(value); }
};
struct Scheduler {
    ScopedComApartment apartment;
    ComPtr<ITaskService> service;
    ComPtr<ITaskFolder> root;
    Scheduler() {
        checkHresult(CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&service)), L"Create scheduler");
        VARIANT empty{}; VariantInit(&empty);
        checkHresult(service->Connect(empty, empty, empty, empty), L"Connect scheduler");
        Bstr name(L"\\"); checkHresult(service->GetFolder(name.value, &root), L"Open task folder");
    }
    ComPtr<IRegisteredTask> get(const wchar_t* name) {
        Bstr taskName(name); ComPtr<IRegisteredTask> task;
        HRESULT result = root->GetTask(taskName.value, &task);
        if (result == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) return {};
        checkHresult(result, L"Read task " + std::wstring(name)); return task;
    }
    void remove(const wchar_t* name) {
        Bstr taskName(name);
        HRESULT result = root->DeleteTask(taskName.value, 0);
        if (result != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) checkHresult(result, L"Delete task " + std::wstring(name));
    }
};

void startResultTask(const WindowsAdapter& adapter) {
    Scheduler scheduler;
    const auto task = scheduler.get(kResultTask);
    if (!task) throw ComponentError(L"The registered user-result task is missing.");
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    const HRESULT result = task->Run(empty, &running);
    if (result == SCHED_E_USER_NOT_LOGGED_ON) {
        adapter.logOperation(L"The target user is not signed in; the result task waits for that user's next sign-in.");
        return;
    }
    checkHresult(result, L"Start the registered ordinary-user result task");
}

void registerTask(const wchar_t* name, const std::wstring& sid,
    const std::filesystem::path& executable, const std::wstring& arguments,
    bool system, bool notification) {
    validateTargetSid(sid);
    Scheduler scheduler; ComPtr<ITaskDefinition> definition;
    checkHresult(scheduler.service->NewTask(0, &definition), L"Create task definition");
    ComPtr<IPrincipal> principal; checkHresult(definition->get_Principal(&principal), L"Get principal");
    Bstr user(system ? L"S-1-5-18" : sid);
    checkHresult(principal->put_UserId(user.value), L"Set task SID");
    const auto logon = system ? TASK_LOGON_SERVICE_ACCOUNT : TASK_LOGON_INTERACTIVE_TOKEN;
    checkHresult(principal->put_LogonType(logon), L"Set task logon");
    checkHresult(principal->put_RunLevel(system ? TASK_RUNLEVEL_HIGHEST : TASK_RUNLEVEL_LUA), L"Set task privilege");
    ComPtr<ITriggerCollection> triggers; checkHresult(definition->get_Triggers(&triggers), L"Get triggers");
    ComPtr<ITrigger> trigger;
    checkHresult(triggers->Create(system ? TASK_TRIGGER_BOOT : TASK_TRIGGER_LOGON, &trigger), L"Create trigger");
    Bstr unlimited(L"PT0S");
    checkHresult(trigger->put_ExecutionTimeLimit(unlimited.value), L"Set unlimited trigger execution time");
    if (!system) {
        ComPtr<ILogonTrigger> login; checkHresult(trigger.As(&login), L"Get logon trigger");
        checkHresult(login->put_UserId(user.value), L"Bind logon trigger SID");
    }
    ComPtr<ITaskSettings> settings; checkHresult(definition->get_Settings(&settings), L"Get settings");
    checkHresult(settings->put_ExecutionTimeLimit(unlimited.value), L"Set unlimited running time");
    checkHresult(settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE), L"Allow battery start");
    checkHresult(settings->put_StopIfGoingOnBatteries(VARIANT_FALSE), L"Allow battery running");
    checkHresult(settings->put_StartWhenAvailable(VARIANT_TRUE), L"Set start availability");
    checkHresult(settings->put_MultipleInstances(wcscmp(name, kFinalizeTask) == 0 ? TASK_INSTANCES_QUEUE : TASK_INSTANCES_IGNORE_NEW), L"Set serialized task execution");
    checkHresult(settings->put_AllowDemandStart(VARIANT_TRUE), L"Allow explicit scheduler startup");
    checkHresult(settings->put_Enabled(VARIANT_TRUE), L"Enable registered task");
    ComPtr<IActionCollection> actions; checkHresult(definition->get_Actions(&actions), L"Get actions");
    ComPtr<IAction> action; checkHresult(actions->Create(TASK_ACTION_EXEC, &action), L"Create executable action");
    ComPtr<IExecAction> execution; checkHresult(action.As(&execution), L"Get executable action");
    Bstr path(executable.wstring()), args(arguments), directory(executable.parent_path().wstring());
    checkHresult(execution->put_Path(path.value), L"Set executable path");
    checkHresult(execution->put_Arguments(args.value), L"Set arguments");
    checkHresult(execution->put_WorkingDirectory(directory.value), L"Set working directory");
    Bstr taskName(name);
    Bstr security(wcscmp(name, kFinalizeTask) == 0
        ? L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + sid + L")"
        : notification
        ? L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGXSD;;;" + sid + L")"
        : L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;" + (system ? L"SY" : sid) + L")");
    VARIANT account{}, empty{}, acl{};
    VariantInit(&account); VariantInit(&empty); VariantInit(&acl);
    account.vt = VT_BSTR; account.bstrVal = user.value;
    acl.vt = VT_BSTR; acl.bstrVal = security.value;
    ComPtr<IRegisteredTask> registered;
    checkHresult(scheduler.root->RegisterTaskDefinition(taskName.value, definition.Get(),
        TASK_CREATE_OR_UPDATE, account, empty, logon, acl, &registered), L"Register task " + std::wstring(name));
}

std::wstring literal(const std::wstring& text) {
    std::wstring result = L"'";
    for (auto value : text) { result += value; if (value == L'\'') result += L"'"; }
    return result + L"'";
}
bool scriptUses(const std::wstring& script, const wchar_t* name) {
    const auto parameter = L"$" + std::wstring(name);
    for (auto offset = script.find(parameter); offset != std::wstring::npos; offset = script.find(parameter, offset + 1)) {
        const auto end = offset + parameter.size();
        if (end == script.size()) return true;
        const auto next = script[end];
        if (!(next >= L'a' && next <= L'z') && !(next >= L'A' && next <= L'Z') &&
            !(next >= L'0' && next <= L'9') && next != L'_') return true;
    }
    return false;
}
std::wstring contractParameters(const std::wstring& script) {
    std::wstring result;
    const auto text = [&result, &script](const wchar_t* name, const wchar_t* value) {
        if (!scriptUses(script, name)) return;
        result += L"$" + std::wstring(name) + L"=" + literal(value) + L"\n";
    };
    const auto number = [&result, &script](const wchar_t* name, std::uint64_t value) {
        if (!scriptUses(script, name)) return;
        result += L"$" + std::wstring(name) + L"=" + std::to_wstring(value) + L"\n";
    };
    text(L"setupRole", unlock_windows::desktop_app::kSetupRole);
    text(L"stPath", kWizardStateRegistryPath.c_str());
    text(L"inPath", kInstalledProductRegistryPath.c_str());
    text(L"rsPath", kResultRegistryPath.c_str());
    text(L"appPath", kApplicationUninstallRegistryPath);
    text(L"rootPath", kProductRegistryPath);
    text(L"finalTask", kFinalizeTask);
    text(L"resultTask", kResultTask);
    text(L"bootTask", kBootTask);
    text(L"mutex", kOperationMutex);
    text(L"ep", kResultEventPrefix);
    text(L"copiedName", kResultCopiedEvent);
    text(L"doneName", kResultDoneEvent);
    text(L"failedName", kResultFailedEvent);
    text(L"svKey", kSchemaVersionValueName);
    text(L"tidKey", kStateTransactionIdValueName);
    text(L"sidKey", kTargetSidValueName);
    text(L"phaseKey", kStatePhaseValueName);
    text(L"pvKey", kPackageVersionValueName);
    text(L"opKey", kOperationValueName);
    text(L"ivKey", kInstalledVersionValueName);
    text(L"wpKey", kStateWizardPathValueName);
    text(L"lastKey", kLastOperationIdValueName);
    text(L"erKey", kStateLastErrorValueName);
    text(L"frKey", kFilesReleasedValueName);
    text(L"snKey", kSnapshotValueName);
    text(L"msgKey", kResultMessageName);
    text(L"logKey", kResultLogName);
    text(L"usKey", kUninstallStringValueName);
    text(L"iconKey", kDisplayIconValueName);
    text(L"dvKey", kDisplayVersionValueName);
    number(L"sv", kWizardStateSchemaVersion);
    number(L"fp", static_cast<std::uint32_t>(WizardPhase::finalizing));
    number(L"uo", static_cast<std::uint32_t>(SetupOperation::uninstall));
    number(L"rv", kCompletionVersion);
    number(L"ff", kCompletionFinishedFlag);
    number(L"sf", kCompletionSuccessFlag);
    number(L"fm", kCompletionFlags);
    number(L"mx", kCompletionMaximumBytes);
    number(L"vw", kCompletionVersionWord);
    number(L"fw", kCompletionFlagsWord);
    number(L"lw", kCompletionLengthsWord);
    number(L"wb", kCompletionWordBytes);
    number(L"cb", kCompletionCharacterBytes);
    number(L"hw", kCompletionHeaderWords);
    if (scriptUses(script, L"tf")) {
        result += L"$tf=@(";
        for (size_t i = 0; i < kCompletionTextFields.size(); ++i) {
            if (i) result += L",";
            result += literal(kCompletionTextFields[i].name);
        }
        result += L")\n";
    }
    if (scriptUses(script, L"children"))
        result += L"$children=@(" + literal(kWizardStateKeyName) + L"," +
            literal(kResultKeyName) + L"," + literal(kInstalledProductKeyName) + L")\n";
    return result;
}
std::wstring prefix(const PackageDeployment& package, const SetupTransactionState& state, const std::wstring& script) {
    if (state.transactionId.empty() || state.transactionId.find_first_not_of(L"0123456789-") != std::wstring::npos)
        throw ComponentError(L"Invalid finalization transaction ID.");
    const std::wstring reader = LR"ps(
$ev=$ep+$id+'-'
function Read-Result{
    $key=$hk.OpenSubKey($rsPath)
    if(!$key){return $null}
    try{$bytes=$key.GetValue($snKey)}finally{$key.Dispose()}
    if(!$bytes){return $null}
    $hb=$hw*$wb
    if($bytes.Length -lt $hb -or $bytes.Length -gt $mx -or [BitConverter]::ToUInt32($bytes,$vw*$wb)-ne $rv){throw 'Invalid setup result snapshot.'}
    $flags=[BitConverter]::ToUInt32($bytes,$fw*$wb)
    if($flags -band(-bnot $fm)){throw 'Invalid setup result flags.'}
    $r=@{Finished=($flags -band $ff)-ne 0;Success=($flags -band $sf)-ne 0};$offset=$hb
    for($i=0;$i -lt $tf.Count;$i++){
        $n=[long][BitConverter]::ToUInt32($bytes,($lw+$i)*$wb)*$cb
        if($n -gt $bytes.Length-$offset){throw 'Truncated setup result.'}
        $r[$tf[$i]]=[Text.Encoding]::Unicode.GetString($bytes,$offset,[int]$n);$offset+=$n
}
    if($offset -ne $bytes.Length -or $r[$tidKey] -ne $id -or $r[$sidKey] -ne $userSid){throw 'Result transaction/user mismatch.'}
    return $r
}
)ps";
    const auto body = reader + script;
    std::wstring result = L"$ErrorActionPreference='Stop'\n$id=" + literal(state.transactionId) +
        L"\n$userSid=" + literal(state.targetSid) + L"\n";
    if (scriptUses(body, L"firstInstall"))
        result += L"$firstInstall=" + std::wstring(state.operation == SetupOperation::install ? L"$true\n" : L"$false\n");
    if (scriptUses(body, L"uninstall"))
        result += L"$uninstall=" + std::wstring(state.operation == SetupOperation::uninstall ? L"$true\n" : L"$false\n");
    if (scriptUses(body, L"setup")) result += L"$setup=" + literal((desktopDirectory() / kInstallerFile).wstring()) + L"\n";
    if (scriptUses(body, L"stage")) result += L"$stage=" + literal(package.transactionDirectory(state).wstring()) + L"\n";
    if (scriptUses(body, L"version")) result += L"$version=" + literal(state.packageVersion) + L"\n";
    result += L"$hk=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)\n";
    return result + contractParameters(body) + body;
}
std::wstring powerShellArguments(const std::wstring& script, bool headless = false) {
    std::wstring compact;
    bool lineStart = true;
    for (const auto character : script) {
        if (lineStart && (character == L' ' || character == L'\t' || character == L'\r')) continue;
        compact += character; lineStart = character == L'\n';
    }
    const int byteCount = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, compact.data(),
        static_cast<int>(compact.size()), nullptr, 0, nullptr, nullptr);
    if (!byteCount) throw ComponentError(L"Could not encode the finalization command.");
    std::string utf8(static_cast<size_t>(byteCount), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, compact.data(), static_cast<int>(compact.size()),
        utf8.data(), byteCount, nullptr, nullptr) != byteCount)
        throw ComponentError(L"Could not encode the finalization command.");
    const auto* bytes = reinterpret_cast<const unsigned char*>(utf8.data());
    const size_t count = utf8.size();
    constexpr wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::wstring encoded;
    for (size_t i = 0; i < count; i += 3) {
        const unsigned value = (unsigned(bytes[i]) << 16) | (i + 1 < count ? unsigned(bytes[i + 1]) << 8 : 0) |
            (i + 2 < count ? bytes[i + 2] : 0);
        encoded += alphabet[(value >> 18) & 63]; encoded += alphabet[(value >> 12) & 63];
        encoded += i + 1 < count ? alphabet[(value >> 6) & 63] : L'=';
        encoded += i + 2 < count ? alphabet[value & 63] : L'=';
    }
    auto arguments = L"-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -Command \"& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + L"'))))\"";
    if (headless) {
        const auto executable = system32Directory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe";
        arguments = L"--headless \"" + executable.wstring() + L"\" " + arguments;
    }
    if (arguments.size() > 32000) throw ComponentError(L"Finalization command exceeds the supported command-line size.");
    return arguments;
}
std::wstring alertScript() {
    return LR"ps(
function Show-SetupAlert($title,$text,$icon){
try{
if(!('SetupUi' -as [type])){
Add-Type -ReferencedAssemblies System.dll,System.Windows.Forms.dll,System.Drawing.dll -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Windows.Forms;
public static class SetupUi{
[DllImport("user32",SetLastError=true)]static extern IntPtr SetThreadDpiAwarenessContext(IntPtr c);
[DllImport("comctl32",CharSet=CharSet.Unicode,PreserveSig=true)]static extern int TaskDialog(IntPtr p,IntPtr h,string t,string i,string c,uint b,IntPtr icon,out int r);
public static void Show(string t,string c,int icon){
IntPtr old=SetThreadDpiAwarenessContext(new IntPtr(-4));
if(old==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
try{
Application.EnableVisualStyles();
int hr=0;
Exception failure=null;
using(Form f=new Form()){
f.Opacity=0;f.ShowInTaskbar=false;f.StartPosition=FormStartPosition.CenterScreen;
f.Shown+=delegate{try{int r;hr=TaskDialog(IntPtr.Zero,IntPtr.Zero,t,null,c,1,new IntPtr(unchecked((ushort)icon)),out r);}catch(Exception e){failure=e;}finally{f.Close();}};
f.ShowDialog();
}
if(failure!=null)throw failure;
Marshal.ThrowExceptionForHR(hr);
}finally{if(SetThreadDpiAwarenessContext(old)==IntPtr.Zero)throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());}
}
}
'@
}
[SetupUi]::Show($title,$text,$icon)
}catch{Write-Error('UI display failure; operation outcome is unchanged: '+$_.Exception.Message)-ErrorAction Continue;exit 1}
}
)ps";
}
std::wstring observerScript(const PackageDeployment& package, const SetupTransactionState& state) {
    return prefix(package, state, LR"ps(
try{
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $userSid){throw 'Only the recorded console user can display this result.'}
    $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folder=$scheduler.GetFolder('\')
    $watch=[Diagnostics.Stopwatch]::StartNew()
    while($true){
        $record=Read-Result
        if($record -and $record.Finished){
            if(!$uninstall){
                $pending=$hk.OpenSubKey($stPath)
                if(!$pending){
                    $arguments=@('--show-result',$id)
                    if($firstInstall -and $record.Success){$arguments += $setupRole}
                    Start-Process -FilePath $setup -ArgumentList $arguments
                    exit 0
}
                $pending.Dispose()
}
            if(!$record.Success){throw($record[$msgKey]+"`r`n"+$record[$logKey])}
}
        $key=$hk.OpenSubKey($stPath)
        $released=$false
        if($key){
            try{$released=$uninstall -and $key.GetValue($tidKey)-eq $id -and
                $key.GetValue($sidKey)-eq $userSid -and $key.GetValue($phaseKey)-eq $fp -and $key.GetValue($frKey)-eq 1}
            finally{$key.Dispose()}
}
        if($released -and $record){break}
        if($watch.Elapsed.TotalSeconds -gt 120){throw 'Setup has not completed. Run setup to inspect the preserved transaction.'}
        Start-Sleep -Milliseconds 200
}
    $security=[Security.AccessControl.EventWaitHandleSecurity]::new()
    $security.SetOwner([Security.Principal.SecurityIdentifier]::new($userSid))
    foreach($sid in @('S-1-5-18','S-1-5-32-544',$userSid)){
        $security.AddAccessRule([Security.AccessControl.EventWaitHandleAccessRule]::new(
            [Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.EventWaitHandleRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
}
    $events=@()
    foreach($name in @($copiedName,$doneName,$failedName)){
        $created=$false
        $event=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::ManualReset,$ev+$name,[ref]$created,$security)
        if(!$created){$event.Dispose();throw 'Another result display owns this transaction handoff.'}
        $events +=$event
}
    try{
        $events[0].Set()|Out-Null
        $folder.GetTask($finalTask).Run($null)|Out-Null
        $index=[Threading.WaitHandle]::WaitAny([Threading.WaitHandle[]]@($events[1],$events[2]),120000)
        if($index -ne 0){
            $failure=Read-Result
            if($failure){throw($failure[$msgKey]+"`r`n"+$failure[$logKey])}
            throw 'Uninstall finalization is incomplete. The transaction remains available for inspection.'
}
}finally{foreach($event in $events){$event.Dispose()}}
}catch{
    Show-SetupAlert 'Setup needs attention' $_.Exception.Message -2
    exit 1
}finally{$hk.Dispose()}
)ps");
}
std::wstring resultObserverScript(const PackageDeployment& package, const SetupTransactionState& state) {
    return alertScript() + observerScript(package, state);
}
std::wstring finalizationRecoveryScript(const PackageDeployment& package, const SetupTransactionState& state) {
    const auto executable = (system32Directory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe").wstring();
    const auto trigger = prefix(package, state, LR"ps(
$state=$hk.OpenSubKey($stPath)
try{if(!$state -or $state.GetValue($tidKey)-ne $id -or $state.GetValue($sidKey)-ne $userSid -or $state.GetValue($phaseKey)-ne $fp){throw 'Finalization transaction changed.'}}
finally{if($state){$state.Dispose()}}
if(!(Read-Result)){throw 'Finalization result is missing.'}
$key=$hk.OpenSubKey($rsPath,$true)
try{
    $snapshot=$key.GetValue($snKey)
    [Array]::Copy([BitConverter]::GetBytes([uint32]0),0,$snapshot,$fw*$wb,$wb)
    $key.SetValue($snKey,$snapshot,[Microsoft.Win32.RegistryValueKind]::Binary);$key.Flush()
}finally{$key.Dispose()}
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$scheduler.GetFolder('\').GetTask($finalTask).Run($null)|Out-Null
$hk.Dispose()
)ps");
    return alertScript() + L"$ErrorActionPreference='Stop'\ntry { $handoff=Start-Process -FilePath " + literal(executable) +
        L" -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList " + literal(powerShellArguments(trigger)) +
        L"\nif ($handoff.ExitCode -ne 0) { throw 'Could not start finalization. Inspect the preserved operation result.' }\n" +
        observerScript(package, state) + LR"ps(
}catch{Show-SetupAlert 'Setup needs attention' $_.Exception.Message -2;exit 1}
)ps";
}
// These fragments form one script: the try/catch and local state span the named stages.
std::wstring finalizationSupportScript() {
    return LR"ps(}
$targets=@(foreach($name in $names){if($systemTargets.ContainsKey($name)){$systemTargets[$name]}else{Join-Path $desktopDir $name}})
$dirs=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach($name in $names){$dir=Split-Path $name -Parent;while($dir){[void]$dirs.Add($dir);$dir=Split-Path $dir -Parent}}
$dirs=@($dirs|Sort-Object -Property Length -Descending)
$lock=$null;$locked=$false;$saved=@{};$app=@{};$taskXml=$null;$folder=$null;$events=@();$log=''
function Write-Result([string]$message,[string]$log,[bool]$finished,[bool]$success){
    $r=@{};$r[$tidKey]=$id;$r[$sidKey]=$userSid;$r[$msgKey]=$message;$r[$logKey]=$log
    $texts=@(foreach($name in $tf){[string]$r[$name]})
    $header=[uint32[]]::new($hw);$header[$vw]=$rv
    if($finished){$header[$fw]=$header[$fw] -bor $ff}
    if($success){$header[$fw]=$header[$fw] -bor $sf}
    $bytes=$hw*$wb
    for($i=0;$i -lt $tf.Count;$i++){$header[$lw+$i]=$texts[$i].Length;$bytes+=[long]$texts[$i].Length*$cb}
    if($bytes -gt $mx){throw 'Completion record too large.'}
    $memory=[IO.MemoryStream]::new();$writer=[IO.BinaryWriter]::new($memory)
    try{
        foreach($word in $header){$writer.Write([uint32]$word)}
        foreach($text in $texts){$writer.Write([Text.Encoding]::Unicode.GetBytes($text))}
        $writer.Flush();$key=$hk.CreateSubKey($rsPath)
        try{$key.SetValue($snKey,$memory.ToArray(),[Microsoft.Win32.RegistryValueKind]::Binary);$key.Flush()}finally{$key.Dispose()}
}finally{$writer.Dispose();$memory.Dispose()}
}
function Check-Dir([string]$path){
    $item=Get-Item -LiteralPath $path -Force
    if(!$item.PSIsContainer -or($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Unsafe directory: $path"}
    $acl=Get-Acl -LiteralPath $path
    $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if($owner -notin @('S-1-5-18','S-1-5-32-544')){throw "Unsafe directory owner: $path"}
    foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
        if($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly){continue}
        if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
([long]$rule.FileSystemRights -band 0x500D0156)-and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544')){throw "Unsafe directory ACL: $path"}
}
}
function Remove-File([string]$path){
    if(!(Test-Path -LiteralPath $path)){return}
    $item=Get-Item -LiteralPath $path -Force
    if($item.PSIsContainer -or($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "Unsafe file: $path"}
    Remove-Item -LiteralPath $path -Force
    if(Test-Path -LiteralPath $path){throw "File remains: $path"}
}
function Remove-Dir([string]$path){
    if(!(Test-Path -LiteralPath $path)){return}
    Check-Dir $path
    if(@(Get-ChildItem -LiteralPath $path -Force).Count){throw "Nonempty directory: $path"}
    Remove-Item -LiteralPath $path -Force
    if(Test-Path -LiteralPath $path){throw "Directory remains: $path"}
}
function Remove-Task([string]$name){
    try{$task=$folder.GetTask($name)}
    catch{
        $taskError=$_.Exception
        while($taskError.InnerException){$taskError=$taskError.InnerException}
        if($taskError.HResult -eq -2147024894){return};throw
}
    $folder.DeleteTask($name,0)
}
)ps";
}
// Seal transaction identity, acquire the maintenance lock and wait for the pinned parent to exit.
std::wstring verifyFinalizationScript() {
    return LR"ps(try{
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'Finalization requires SYSTEM.'}
    $lock=[Threading.Mutex]::new($false,$mutex)
    try{$locked=$lock.WaitOne(30000)}catch [Threading.AbandonedMutexException]{$locked=$true}
    if(!$locked){throw 'Setup lock timed out.'}
    $key=$hk.OpenSubKey($stPath,$true)
    if(!$key){throw 'Finalization state is missing.'}
    try{
        if($key.GetValue($svKey)-ne $sv -or $key.GetValue($tidKey)-ne $id -or
            $key.GetValue($sidKey)-ne $userSid -or $key.GetValue($phaseKey)-ne $fp -or
            $key.GetValue($pvKey)-ne $version -or($key.GetValue($opKey)-eq $uo)-ne $uninstall){throw 'Sealed transaction mismatch.'}
        foreach($name in $key.GetValueNames()){$saved[$name]=@($key.GetValue($name),$key.GetValueKind($name))}
}finally{$key.Dispose()}
    $prior=Read-Result
    if($prior){$log=$prior[$logKey]}
    $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folder=$scheduler.GetFolder('\')
    $taskXml=$folder.GetTask($finalTask).Xml
    $key=$hk.OpenSubKey($appPath)
    if(!$key){throw 'Missing uninstall entry.'}
    try{foreach($name in $key.GetValueNames()){$app[$name]=@($key.GetValue($name),$key.GetValueKind($name))}}finally{$key.Dispose()}
    $parent=$null
    try{$parent=[Diagnostics.Process]::GetProcessById($parentId)}catch [ArgumentException]{}
    if($parent){
        try{
            $handle=$parent.Handle
            if($parent.StartTime.ToUniversalTime().ToFileTimeUtc()-eq $created){
                if($parent.MainModule.FileName -ine $image){throw 'Parent image changed.'}
                if(!$parent.WaitForExit(30000)){throw 'Parent exit timed out.'}
}
}finally{$parent.Dispose()}
}
)ps";
}
// Delete only manifest-owned files and empty protected directories; unknown contents are errors.
std::wstring releaseTransactionFilesScript() {
    return LR"ps(    if(Test-Path -LiteralPath $stage){
        Check-Dir $productDir
        Check-Dir(Split-Path -Path(Split-Path -Path $stage -Parent)-Parent)
        Check-Dir(Split-Path -Path $stage -Parent)
        Check-Dir $stage
        foreach($relative in (@('')+$dirs)){
            $parent=if($relative){Join-Path $stage $relative}else{$stage}
            if(!(Test-Path -LiteralPath $parent)){continue}
            Check-Dir $parent
            foreach($file in Get-ChildItem -LiteralPath $parent -Force){
                $child=if($relative){Join-Path $relative $file.Name}else{$file.Name}
                if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint)-or
                    ($file.PSIsContainer -and $child -notin $dirs)-or(!$file.PSIsContainer -and $child -notin $names)){throw 'Unknown staged file.'}
}
}
        foreach($name in $names){Remove-File(Join-Path -Path $stage -ChildPath $name)}
        foreach($dir in $dirs){Remove-Dir(Join-Path $stage $dir)}
        Remove-Dir $stage
}
    Remove-Dir(Split-Path -Path $stage -Parent)
    Remove-Dir(Split-Path -Path(Split-Path -Path $stage -Parent)-Parent)
    foreach($path in $targets){
        if($uninstall -and(Test-Path -LiteralPath $path)){throw "Program remains: $path"}
        if(Test-Path -LiteralPath($path+'.update')){throw "Replacement remains: $path.update"}
}
)ps";
}
// Install commits a formal record; uninstall waits for the user to copy the result before deletion.
std::wstring commitFinalizationScript() {
    return LR"ps(    if($uninstall){
        foreach($dir in $dirs){Remove-Dir(Join-Path $desktopDir $dir)}
        Remove-Dir $desktopDir;Remove-Dir $vaultDir;Remove-Dir $productDir
        $key=$hk.OpenSubKey($stPath,$true)
        try{$key.SetValue($frKey,1,[Microsoft.Win32.RegistryValueKind]::DWord);$key.Flush()}finally{$key.Dispose()}
        Remove-Task $bootTask
        Write-Result 'Removal verified; handoff pending.' $log $false $false
        try{$copied=[Threading.EventWaitHandle]::OpenExisting($ev+$copiedName,'ReadPermissions,Synchronize')}
        catch [Threading.WaitHandleCannotBeOpenedException]{exit 0}
        $events +=$copied
        $owner=$copied.GetAccessControl().GetOwner([Security.Principal.SecurityIdentifier]).Value
        if($owner -ne $userSid -or !$copied.WaitOne(0)){throw 'Untrusted result handoff.'}
        $done=[Threading.EventWaitHandle]::OpenExisting($ev+$doneName);$failed=[Threading.EventWaitHandle]::OpenExisting($ev+$failedName)
        $events +=$done;$events +=$failed
        $root=$hk.OpenSubKey($rootPath)
        try{
            if(@($root.GetValueNames()).Count -or @($root.GetSubKeyNames()|Where-Object{$_ -notin $children}).Count){throw 'Unknown product registry data.'}
}finally{$root.Dispose()}
        Remove-Task $resultTask;Remove-Task $finalTask
        $hk.DeleteSubKeyTree($rootPath,$false)
        $hk.DeleteSubKeyTree($appPath,$false)
        if($hk.OpenSubKey($appPath)-or $hk.OpenSubKey($rootPath)){throw 'Registry removal failed.'}
        $done.Set()|Out-Null
}else{
        $key=$hk.CreateSubKey($inPath)
        try{
            $key.SetValue($svKey,$sv,[Microsoft.Win32.RegistryValueKind]::DWord)
            $key.SetValue($sidKey,$userSid)
            $key.SetValue($ivKey,$version)
            $key.SetValue($wpKey,$setup)
            $key.SetValue($lastKey,$id);$key.Flush()
            if($key.GetValue($ivKey)-ne $version -or $key.GetValue($sidKey)-ne $userSid -or $key.GetValue($wpKey)-ne $setup){throw 'Installed record mismatch.'}
}finally{$key.Dispose()}
        $key=$hk.OpenSubKey($appPath,$true)
        try{$key.SetValue($usKey,'"'+$setup+'" --uninstall');$key.SetValue($iconKey,'"'+$setup+'",0');$key.SetValue($dvKey,$version);$key.Flush()}finally{$key.Dispose()}
        Remove-Task $bootTask;Remove-Task $finalTask
        Write-Result('Product '+$version+' installed; deployment and cleanup verified.')$log $true $true
        $hk.DeleteSubKeyTree($stPath,$false)
}
    exit 0
)ps";
}
// Restore continuation evidence on failure rather than rolling back deployed product files.
std::wstring preserveFinalizationFailureScript() {
    return LR"ps(}catch{
    $detail=$_.Exception.Message
    if(!$saved.Count){Write-Error('Finalization refused: '+$detail)-ErrorAction Continue;exit 1}
    try{
        $key=$hk.CreateSubKey($stPath)
        try{
            foreach($name in $saved.Keys){$key.SetValue($name,$saved[$name][0],$saved[$name][1])}
            $key.SetValue($erKey,'Finalization incomplete: '+$detail);$key.SetValue($phaseKey,$fp,[Microsoft.Win32.RegistryValueKind]::DWord);$key.Flush()
}finally{$key.Dispose()}
        if($app.Count){
            $key=$hk.CreateSubKey($appPath)
            try{foreach($name in $app.Keys){$key.SetValue($name,$app[$name][0],$app[$name][1])};$key.Flush()}finally{$key.Dispose()}
}
        if($taskXml -and $folder){
            $folder.RegisterTask($finalTask,$taskXml,6,'S-1-5-18',$null,5,
                'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGX;;;'+$userSid+')')|Out-Null
}
        Write-Result('Finalization incomplete: '+$detail)$log $true $false
        try{$failed=[Threading.EventWaitHandle]::OpenExisting($ev+$failedName);$failed.Set()|Out-Null;$failed.Dispose()}
        catch [Threading.WaitHandleCannotBeOpenedException]{}
}catch{Write-Error($detail+'; failed to persist error: '+$_.Exception.Message)-ErrorAction Continue}
    exit 1
}finally{
    foreach($event in $events){$event.Dispose()}
    if($locked){$lock.ReleaseMutex()}
    if($lock){$lock.Dispose()}
    $hk.Dispose()
}
)ps";
}
std::wstring finalizationScript(const WindowsAdapter& adapter, const PackageDeployment& package, const SetupTransactionState& state) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) throw ComponentError(L"Cannot pin finalization parent creation time.");
    ULARGE_INTEGER stamp{}; stamp.LowPart = created.dwLowDateTime; stamp.HighPart = created.dwHighDateTime;
    std::wstring script = L"$parentId=" + std::to_wstring(GetCurrentProcessId()) +
        L"\n$created=" + std::to_wstring(stamp.QuadPart) + L"\n$image=" + literal(adapter.wizardPath().wstring()) +
        L"\n$productDir=" + literal(productDataDirectory().wstring()) + L"\n$desktopDir=" + literal(desktopDirectory().wstring()) +
        L"\n$vaultDir=" + literal((setupKnownFolder(FOLDERID_ProgramData) / unlock_windows::saved_credential::kVaultDirectoryName).wstring()) + L"\n$names=@(";
    std::map<std::wstring, std::vector<std::wstring>> groups;
    for (const auto& entry : packageFiles()) {
        (void)adapter.componentTarget(entry.component());
        const std::filesystem::path path(entry.name);
        groups[path.filename().wstring()].push_back(path.parent_path().wstring());
    }
    for (const auto& [filename, parents] : groups) {
        if (parents.size() == 1) script += literal((std::filesystem::path(parents[0]) / filename).wstring()) + L";";
        else {
            script += L"@(";
            for (size_t index = 0; index < parents.size(); ++index) {
                if (index) script += L",";
                script += literal(parents[index]);
            }
            script += L")|ForEach-Object{if($_){Join-Path $_ " + literal(filename) +
                L"}else{" + literal(filename) + L"}};";
        }
    }
    script += L")\n$systemTargets=@{";
    for (const auto& entry : packageFiles())
        if (!entry.desktopTool)
            script += literal(entry.name) + L"=" + literal(adapter.componentTarget(entry.component()).wstring()) + L";";
    script += finalizationSupportScript() + verifyFinalizationScript() +
        releaseTransactionFilesScript() + commitFinalizationScript() + preserveFinalizationFailureScript();
    return prefix(package, state, script);
}
} // namespace
bool SetupFinalization::continuationTaskExists() const {
    Scheduler scheduler;
    return scheduler.get(kBootTask).Get() != nullptr;
}
void SetupFinalization::registerContinuationTask(const SetupTransactionState& state) const {
    adapter_.logOperation(L"Register SYSTEM boot task and ordinary-user result task for SID " + state.targetSid);
    validateTargetSid(state.targetSid);
    if (std::filesystem::path(state.wizardPath) != package_.transactionDirectory(state) / kInstallerFile)
        throw ComponentError(L"Reboot continuation must use this transaction's protected staged installer.");
    registerTask(kBootTask, state.targetSid, state.wizardPath,
        L"--resume-operation " + state.transactionId, true, false);
    registerResultTask(state);
}
// Result observation runs as the ordinary target user; cleanup authority remains with SYSTEM.
void SetupFinalization::registerResultTask(const SetupTransactionState& state) const {
    registerTask(kResultTask, state.targetSid, system32Directory() / L"conhost.exe",
        powerShellArguments(resultObserverScript(package_, state), true), false, true);
}
void SetupFinalization::startFinalization(const SetupTransactionState& state) const {
    adapter_.assertSupportedAdministratorEnvironment();
    const auto current = store_.readTransaction();
    if (!current || current->phase != WizardPhase::finalizing || current->transactionId != state.transactionId ||
        current->targetSid != state.targetSid || current->packageVersion != state.packageVersion)
        throw ComponentError(L"Finalization requires the matching verified deployment transaction.");
    registerTask(kFinalizeTask, state.targetSid, system32Directory() / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe",
        powerShellArguments(finalizationScript(adapter_, package_, state)), true, false);
    registerResultTask(state);
    registerFinalizationUninstall(state);
    retryFinalization(state);
}
void SetupFinalization::runContinuation(const SetupTransactionState& state) const {
    const auto current = store_.readTransaction();
    if (!current || current->transactionId != state.transactionId || store_.transactionRebootRequired())
        throw ComponentError(L"Continuation does not match a reboot-completed transaction.");
    Scheduler scheduler; const auto task = scheduler.get(kBootTask);
    if (!task) throw ComponentError(L"SYSTEM continuation task is missing. No new transaction was started.");
    auto record = store_.readCompletion();
    if (!record || record->transactionId != state.transactionId) throw ComponentError(L"Continuation result record is missing or belongs to another transaction.");
    record->finished = record->success = false;
    record->message = L"Continuing the registered operation..."; store_.writeCompletion(*record);
    registerResultTask(state); startResultTask(adapter_);
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    checkHresult(task->Run(empty, &running), L"Continue the registered SYSTEM operation");
}
bool SetupFinalization::finalizationTaskExists() const {
    Scheduler scheduler; return scheduler.get(kFinalizeTask).Get() != nullptr;
}
void SetupFinalization::retryFinalization(const SetupTransactionState& state) const {
    const auto current = store_.readTransaction();
    if (!current || current->transactionId != state.transactionId || current->phase != WizardPhase::finalizing)
        throw ComponentError(L"Finalization does not match the registered transaction.");
    Scheduler scheduler; const auto task = scheduler.get(kFinalizeTask);
    if (!task) { startFinalization(state); return; }
    registerResultTask(state);
    auto record = store_.readCompletion();
    if (!record || record->transactionId != state.transactionId) throw ComponentError(L"Finalization result record is missing or belongs to another transaction.");
    record->finished = record->success = false;
    record->message = L"Continuing finalization..."; store_.writeCompletion(*record);
    startResultTask(adapter_);
    VARIANT empty{}; VariantInit(&empty); ComPtr<IRunningTask> running;
    checkHresult(task->Run(empty, &running), L"Run this transaction's finalization task");
}
void SetupFinalization::registerFinalizationUninstall(const SetupTransactionState& state) const {
    const auto executable = system32Directory() / L"conhost.exe";
    if (!fileExists(executable)) fail(L"System console host is missing; finalization cannot start.");
    adapter_.registerApplicationUninstall(executable, state.installedVersion.empty() ? state.packageVersion : state.installedVersion);
    writeRegistryString(HKEY_LOCAL_MACHINE, kApplicationUninstallRegistryPath, kUninstallStringValueName,
        L"\"" + executable.wstring() + L"\" " + powerShellArguments(finalizationRecoveryScript(package_, state), true));
}

void SetupFinalization::acknowledgeCompletion(const std::wstring& transaction) const {
    const auto result = store_.readCompletion();
    if (!result || !result->finished || result->transactionId != transaction ||
        result->targetSid != adapter_.currentUserSid())
        throw ComponentError(L"Only the target user can dismiss the matching completed result.");
    // Only the recorded user may consume the one-time result and remove its observer task.
    Scheduler scheduler; scheduler.remove(kResultTask);
    store_.removeCompletion();
}
void SetupFinalization::startTrayForCompletedOperation(const std::wstring& transaction, bool setup) const {
    const auto result = store_.readCompletion();
    if (!result || !result->finished || !result->success || result->transactionId != transaction)
        throw ComponentError(L"Bluetooth startup requires the matching successful completion result.");
    if (store_.readTransaction())
        throw ComponentError(L"Bluetooth startup does not match the completed installation.");
    const auto installed = store_.readInstalledProduct();
    if (!installed) return;
    if (installed->targetSid != result->targetSid)
        throw ComponentError(L"Bluetooth startup does not match the completed installation.");
    adapter_.startTray(installed->targetSid, setup);
}
}
