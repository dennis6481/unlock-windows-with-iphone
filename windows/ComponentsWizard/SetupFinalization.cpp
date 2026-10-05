// Created by Rui MA on 04 Oct 2026

#define UNICODE
#define _UNICODE
#include "SetupFinalization.h"
#include "../Resources/resource.h"
#include "InstallationPaths.h"
#include "../SavedCredential/SavedCredentialVault.h"
#include <Windows.h>
#include <array>

namespace unlock::components {
namespace {
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
    text(L"productName", UNLOCK_PRODUCT_DISPLAY_NAME);
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
std::wstring prefix(const WindowsAdapter& adapter, const WizardState& state, const std::wstring& script) {
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
    if (scriptUses(body, L"uninstall"))
        result += L"$uninstall=" + std::wstring(state.operation == SetupOperation::uninstall ? L"$true\n" : L"$false\n");
    if (scriptUses(body, L"setup")) result += L"$setup=" + literal((desktopDirectory() / kInstallerFile).wstring()) + L"\n";
    if (scriptUses(body, L"stage")) result += L"$stage=" + literal(adapter.updateDirectory(state).wstring()) + L"\n";
    if (scriptUses(body, L"version")) result += L"$version=" + literal(state.packageVersion) + L"\n";
    result += L"$hk=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,[Microsoft.Win32.RegistryView]::Registry64)\n";
    return result + contractParameters(body) + body;
}
}
std::wstring encodedPowerShell(const std::wstring& script) {
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
    if (arguments.size() > 32000) throw ComponentError(L"Finalization command exceeds the supported command-line size.");
    return arguments;
}
namespace {
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
std::wstring observerScript(const WindowsAdapter& adapter, const WizardState& state) {
    return prefix(adapter, state, LR"ps(
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
                    Start-Process -FilePath $setup -ArgumentList @('--show-result',$id)
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
        Show-SetupAlert $productName 'Uninstall completed and verified. Windows credentials, phone enrollment and computer identity were removed. Remove the computer record on your iPhone separately.' -3
}finally{foreach($event in $events){$event.Dispose()}}
}catch{
    Show-SetupAlert 'Setup needs attention' $_.Exception.Message -2
    exit 1
}finally{$hk.Dispose()}
)ps");
}
}
std::wstring resultObserverScript(const WindowsAdapter& adapter, const WizardState& state) {
    return alertScript() + observerScript(adapter, state);
}
std::wstring finalizationRecoveryScript(const WindowsAdapter& adapter, const WizardState& state) {
    std::array<wchar_t, 32768> directory{};
    if (!GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()))) throw ComponentError(L"Cannot resolve system PowerShell.");
    const auto executable = (std::filesystem::path(directory.data()) / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe").wstring();
    const auto trigger = prefix(adapter, state, LR"ps(
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
        L" -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList " + literal(encodedPowerShell(trigger)) +
        L"\nif ($handoff.ExitCode -ne 0) { throw 'Could not start finalization. Inspect the preserved operation result.' }\n" +
        observerScript(adapter, state) + LR"ps(
}catch{Show-SetupAlert 'Setup needs attention' $_.Exception.Message -2;exit 1}
)ps";
}
std::wstring finalizationScript(const WindowsAdapter& adapter, const WizardState& state) {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) throw ComponentError(L"Cannot pin finalization parent creation time.");
    ULARGE_INTEGER stamp{}; stamp.LowPart = created.dwLowDateTime; stamp.HighPart = created.dwHighDateTime;
    std::wstring script = L"$parentId=" + std::to_wstring(GetCurrentProcessId()) +
        L"\n$created=" + std::to_wstring(stamp.QuadPart) + L"\n$image=" + literal(adapter.wizardPath().wstring()) +
        L"\n$productDir=" + literal(productDataDirectory().wstring()) + L"\n$desktopDir=" + literal(desktopDirectory().wstring()) +
        L"\n$vaultDir=" + literal((setupKnownFolder(FOLDERID_ProgramData) / unlock_windows::saved_credential::kVaultDirectoryName).wstring()) + L"\n$names=@(";
    for (size_t i = 0; i < kComponentFiles.size(); ++i) {
        if (i) script += L",";
        script += literal(kComponentFiles[i].name);
    }
    script += L")\n$targets=@(";
    for (size_t i = 0; i < kComponentFiles.size(); ++i) {
        if (i) script += L",";
        script += literal(adapter.componentTarget(kComponentFiles[i]).wstring());
    }
    script += LR"ps()
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
try{
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
    if(Test-Path -LiteralPath $stage){
        Check-Dir $productDir
        Check-Dir(Split-Path -Path(Split-Path -Path $stage -Parent)-Parent)
        Check-Dir(Split-Path -Path $stage -Parent)
        Check-Dir $stage
        foreach($file in Get-ChildItem -LiteralPath $stage -Force){
            if($file.Name -notin $names -or $file.PSIsContainer -or($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unknown staged file.'}
}
        foreach($name in $names){Remove-File(Join-Path -Path $stage -ChildPath $name)}
        Remove-Dir $stage
}
    Remove-Dir(Split-Path -Path $stage -Parent)
    Remove-Dir(Split-Path -Path(Split-Path -Path $stage -Parent)-Parent)
    foreach($path in $targets){
        if($uninstall -and(Test-Path -LiteralPath $path)){throw "Program remains: $path"}
        if(Test-Path -LiteralPath($path+'.update')){throw "Replacement remains: $path.update"}
}
    if($uninstall){
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
}catch{
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
    return prefix(adapter, state, script);
}
}
