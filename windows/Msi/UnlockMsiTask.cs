using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public sealed class UnlockMsiTask : Task
{
    [Required] public string Operation { get; set; }
    [Required] public string WindowsDirectory { get; set; }
    [Required] public string BuildDirectory { get; set; }
    [Required] public string Architecture { get; set; }
    [Required] public string ProductVersion { get; set; }
    [Required] public string ReleaseVersion { get; set; }
    [Required] public string MinimumWindowsBuild { get; set; }
    [Required] public string MainAppFile { get; set; }
    [Required] public string CredentialProviderFile { get; set; }
    [Required] public string SavedCredentialServiceFile { get; set; }
    [Required] public string InstallerFile { get; set; }
    [Required] public string PackagePath { get; set; }
    [Required] public string SetupFile { get; set; }

    string MsiDirectory { get { return Path.Combine(WindowsDirectory, "Msi"); } }
    sealed class Payload
    {
        public string Name, Path;
        public bool Product;
    }

    public override bool Execute()
    {
        try
        {
            Require(Architecture == "x64" || Architecture == "arm64", "Unsupported MSI architecture.");
            BuildDirectory = Path.GetFullPath(BuildDirectory);
            if (Operation == "Generate") Generate();
            else if (Operation == "Validate") Validate();
            else throw new InvalidOperationException("Unknown MSI task operation: " + Operation);
            return true;
        }
        catch (Exception error) { Log.LogErrorFromException(error, true); return false; }
    }

    static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    static Dictionary<string, string> HeaderStrings(string path)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (Match match in Regex.Matches(File.ReadAllText(path), "wchar_t\\s+(\\w+)\\[\\]\\s*=\\s*L\"([^\"]+)\";"))
            values.Add(match.Groups[1].Value, match.Groups[2].Value.Replace("\\\\", "\\"));
        return values;
    }

    static string Hash(string path)
    {
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(path)) return BitConverter.ToString(sha.ComputeHash(stream));
    }

    static string PayloadId(string name)
    {
        using (var sha = SHA256.Create())
            return "P" + BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(name.ToLowerInvariant()))).Replace("-", "").Substring(0, 32);
    }

    static bool IsPe(string path)
    {
        using (var stream = File.OpenRead(path)) return stream.ReadByte() == 0x4d && stream.ReadByte() == 0x5a;
    }

    // Classify resource-only PE containers and ARM64X from their headers, not their filenames.
    static string PeArchitecture(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        Require(data.Length >= 0x40 && BitConverter.ToUInt16(data, 0) == 0x5a4d, "Invalid PE DOS header: " + path);
        int pe = BitConverter.ToInt32(data, 0x3c);
        Require(pe >= 0x40 && pe <= data.Length - 24 && BitConverter.ToUInt32(data, pe) == 0x4550, "Invalid PE signature: " + path);
        ushort machine = BitConverter.ToUInt16(data, pe + 4);
        int count = BitConverter.ToUInt16(data, pe + 6), optionalSize = BitConverter.ToUInt16(data, pe + 20);
        int optional = pe + 24, sections = optional + optionalSize;
        Require(optionalSize >= 20 && sections <= data.Length - 40 * count, "Truncated PE optional header or sections: " + path);
        ushort magic = BitConverter.ToUInt16(data, optional);
        Require(magic == 0x10b || magic == 0x20b, "Unsupported PE optional header: " + path);
        bool native = BitConverter.ToUInt32(data, optional + 16) != 0;
        for (int i = 0; i < count; ++i) native |= (BitConverter.ToUInt32(data, sections + 40 * i + 36) & 0x20000000) != 0;
        if (!native) return "neutral";
        if (machine == 0xaa64 && magic == 0x20b && optionalSize >= 200)
        {
            uint configRva = BitConverter.ToUInt32(data, optional + 192);
            for (int i = 0; configRva != 0 && i < count; ++i)
            {
                int section = sections + 40 * i;
                uint va = BitConverter.ToUInt32(data, section + 12), rawSize = BitConverter.ToUInt32(data, section + 16), raw = BitConverter.ToUInt32(data, section + 20);
                if (configRva < va || (long)configRva - va > (long)rawSize - 232) continue;
                long config = (long)raw + configRva - va;
                if (config > data.Length - 232 || BitConverter.ToUInt32(data, (int)config) < 232) break;
                uint relocOffset = BitConverter.ToUInt32(data, (int)config + 224);
                int relocSection = BitConverter.ToUInt16(data, (int)config + 228);
                if (relocSection == 0 || relocSection > count) break;
                int relocHeader = sections + 40 * (relocSection - 1);
                long table = (long)BitConverter.ToUInt32(data, relocHeader + 20) + relocOffset;
                long available = (long)BitConverter.ToUInt32(data, relocHeader + 16) - relocOffset;
                if (available < 8 || table > data.Length - 8) break;
                uint tableSize = BitConverter.ToUInt32(data, (int)table + 4);
                if (BitConverter.ToUInt32(data, (int)table) != 1 || tableSize > available - 8 || tableSize > data.Length - table - 8) break;
                long cursor = table + 8, end = cursor + tableSize;
                while (cursor <= end - 12)
                {
                    ulong symbol = BitConverter.ToUInt64(data, (int)cursor);
                    uint fixups = BitConverter.ToUInt32(data, (int)cursor + 8);
                    Require(fixups <= end - cursor - 12, "Truncated hybrid PE fixups: " + path);
                    if (symbol == 6) return "arm64x";
                    cursor += 12 + fixups;
                }
                break;
            }
        }
        if (machine == 0x8664) return "x64";
        if (machine == 0xaa64) return "arm64";
        throw new InvalidOperationException("Unsupported PE machine type " + machine.ToString("X4") + ": " + path);
    }

    void CheckArchitecture(string path, bool product)
    {
        string actual = PeArchitecture(path);
        Require(actual == Architecture || (!product && (actual == "neutral" || actual == "arm64x")),
            "Wrong payload PE architecture (" + actual + ", expected " + Architecture + "): " + path);
    }

    List<Payload> GetPayload()
    {
        string headerPath = Path.Combine(WindowsDirectory, "ComponentFiles.h");
        var names = HeaderStrings(headerPath);
        var entries = new List<Payload>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Match manifest = Regex.Match(File.ReadAllText(headerPath), @"(?s)kComponentFiles\{\{(.*?)\}\};");
        Require(manifest.Success, "Missing component filename contract.");
        foreach (Match match in Regex.Matches(manifest.Groups[1].Value, @"\b(k\w+File)\b"))
        {
            string name;
            Require(names.TryGetValue(match.Value, out name) && !String.IsNullOrEmpty(name) && seen.Add(name), "Invalid component filename contract.");
            entries.Add(new Payload { Name = name, Path = Path.Combine(BuildDirectory, name), Product = true });
        }
        Require(entries.Count != 0, "Empty component filename contract.");
        string policy = @"(?!(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$))[^<>:""/\\|?*\x00-\x1F]*[^<>:""/\\|?*\x00-\x1F. ]";
        foreach (string line in File.ReadAllLines(Path.Combine(BuildDirectory, "DesktopApp.files")))
        {
            string name = line.Replace('/', '\\');
            Require(!Path.IsPathRooted(name) && name.Split('\\').All(p => Regex.IsMatch(p, @"\A(?:" + policy + @")\z")), "Unsafe payload path: " + name);
            if (name == MainAppFile) continue;
            Require(seen.Add(name), "Duplicate payload path: " + name);
            entries.Add(new Payload { Name = name, Path = Path.Combine(BuildDirectory, name) });
        }
        foreach (var entry in entries)
        {
            var file = new FileInfo(entry.Path);
            Require(file.Exists && (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) == 0, "Unsafe or missing payload file: " + entry.Path);
            for (var parent = file.Directory; parent != null && parent.FullName.Length >= BuildDirectory.Length; parent = parent.Parent)
                Require((parent.Attributes & FileAttributes.ReparsePoint) == 0, "Unsafe payload directory: " + parent.FullName);
            bool pe = IsPe(entry.Path);
            if (pe) CheckArchitecture(entry.Path, entry.Product);
            if (!entry.Product) continue;
            Require(pe, "Product component is not PE: " + entry.Path);
            var version = FileVersionInfo.GetVersionInfo(entry.Path);
            Require(version.FileVersion == ProductVersion && version.ProductVersion == ProductVersion &&
                new Version(version.FileMajorPart, version.FileMinorPart, version.FileBuildPart, version.FilePrivatePart).ToString() == ProductVersion &&
                new Version(version.ProductMajorPart, version.ProductMinorPart, version.ProductBuildPart, version.ProductPrivatePart).ToString() == ProductVersion,
                "Mixed product version: " + entry.Path);
        }
        return entries;
    }

    static string Xml(string value) { return SecurityElement.Escape(value); }
    static void WriteIfDifferent(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        if (!File.Exists(path) || File.ReadAllText(path) != content) File.WriteAllText(path, content, new UTF8Encoding(false));
    }

    void Generate()
    {
        var entries = GetPayload();
        var identity = HeaderStrings(Path.Combine(WindowsDirectory, "ProductIdentity.h"));
        var contract = HeaderStrings(Path.Combine(MsiDirectory, "MsiContract.h"));
        var ipc = HeaderStrings(Path.Combine(WindowsDirectory, "SavedCredential", "SavedCredentialIpc.h"));
        string provider = Regex.Match(File.ReadAllText(Path.Combine(WindowsDirectory, "CredentialProvider", "UnlockCredentialProvider.h")), @"(?s)kUnlockCredentialProviderClsid\{(.*?)\};").Groups[1].Value;
        var guid = Regex.Matches(provider, "0x([0-9a-fA-F]+)").Cast<Match>().Select(m => Convert.ToUInt32(m.Groups[1].Value, 16)).ToArray();
        Require(guid.Length == 11, "Invalid Credential Provider GUID contract.");
        string clsid = "{" + String.Format("{0:x8}-{1:x4}-{2:x4}-{3:x2}{4:x2}-{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}", guid.Cast<object>().ToArray()) + "}";
        Guid.Parse(clsid);
        string name = Regex.Match(File.ReadAllText(Path.Combine(WindowsDirectory, "Resources", "resource.h")), "#define UNLOCK_PRODUCT_NAME \"([^\"]+)\"").Groups[1].Value.Replace("\\x00ae", "\u00ae");
        Require(name.Length != 0, "Missing product display name.");
        var definitions = new SortedDictionary<string, string>(StringComparer.Ordinal) {
            { "ProductName", name }, { "MsiVersion", ReleaseVersion }, { "FullVersion", ProductVersion },
            { "MinimumWindowsBuild", MinimumWindowsBuild }, { "DesktopDirectoryName", identity["kDesktopDirectoryName"] },
            { "InstalledProductRegistryPath", identity["kInstalledProductRegistryPath"] }, { "TargetSidValueName", identity["kTargetSidValueName"] },
            { "InstalledVersionValueName", identity["kInstalledVersionValueName"] }, { "DeploymentKindValueName", identity["kDeploymentKindValueName"] },
            { "MsiProductCodeValueName", identity["kMsiProductCodeValueName"] }, { "MainAppFile", MainAppFile },
            { "MainAppSource", Path.Combine(BuildDirectory, MainAppFile) }, { "UpgradeCode", contract[Architecture == "x64" ? "kX64UpgradeCode" : "kArm64UpgradeCode"] }
        };
        var include = new StringBuilder("<Include xmlns=\"http://wixtoolset.org/schemas/v4/wxs\">\r\n");
        foreach (var definition in definitions)
        {
            Require(!String.IsNullOrEmpty(definition.Value), "Missing MSI definition: " + definition.Key);
            include.AppendFormat("<?define {0}=\"{1}\" ?>\r\n", definition.Key, Xml(definition.Value));
        }
        include.Append("</Include>\r\n");
        WriteIfDifferent(Path.Combine(BuildDirectory, "generated", "Product.wxi"), include.ToString());
        var lines = new StringBuilder("<Wix xmlns=\"http://wixtoolset.org/schemas/v4/wxs\"><Fragment>\r\n");
        var components = new List<string>();
        var directories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            string id = PayloadId(entry.Name), directoryId = "DesktopDirectory", relative = "";
            components.Add(id);
            string[] parts = entry.Name.Split('\\');
            for (int i = 0; i < parts.Length - 1; ++i)
            {
                relative += "\\" + parts[i];
                string childId = PayloadId(relative);
                if (directories.Add(relative)) lines.AppendFormat("<DirectoryRef Id=\"{0}\"><Directory Id=\"{1}\" Name=\"{2}\" /></DirectoryRef>\r\n", directoryId, childId, Xml(parts[i]));
                directoryId = childId;
            }
            lines.AppendFormat("<DirectoryRef Id=\"{0}\"><Component Id=\"{1}\" Guid=\"*\" Bitness=\"always64\">\r\n", directoryId, id);
            if (entry.Name == MainAppFile)
            {
                lines.AppendFormat("<File Id=\"F{0}\" Source=\"{1}\" KeyPath=\"yes\">", id, Xml(entry.Path));
                lines.AppendFormat("<Shortcut Id=\"MainShortcut\" Directory=\"ProgramMenuFolder\" Name=\"{0}\" Advertise=\"yes\" WorkingDirectory=\"DesktopDirectory\" Icon=\"AppIcon.exe\" /></File>\r\n", Xml(name));
            }
            else lines.AppendFormat("<File Id=\"F{0}\" Source=\"{1}\" KeyPath=\"yes\" />\r\n", id, Xml(entry.Path));
            if (entry.Name == CredentialProviderFile)
            {
                string providerKey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\" + clsid;
                string comKey = "SOFTWARE\\Classes\\CLSID\\" + clsid;
                lines.AppendFormat("<RegistryKey Root=\"HKLM\" Key=\"{0}\" ForceDeleteOnUninstall=\"yes\"><RegistryValue Type=\"string\" Value=\"{1}\" /></RegistryKey>\r\n", providerKey, Xml(name));
                lines.AppendFormat("<RegistryKey Root=\"HKLM\" Key=\"{0}\" ForceDeleteOnUninstall=\"yes\"><RegistryValue Type=\"string\" Value=\"{1}\" />", comKey, Xml(name));
                lines.AppendFormat("<RegistryKey Key=\"InprocServer32\"><RegistryValue Type=\"string\" Value=\"[#F{0}]\" />", id);
                lines.Append("<RegistryValue Name=\"ThreadingModel\" Type=\"string\" Value=\"Apartment\" /></RegistryKey></RegistryKey>\r\n");
            }
            if (entry.Name == SavedCredentialServiceFile)
            {
                lines.AppendFormat("<ServiceInstall Id=\"CredentialService\" Name=\"{0}\" DisplayName=\"{1}\" Type=\"ownProcess\" Start=\"auto\" ErrorControl=\"normal\" Account=\"LocalSystem\" Vital=\"yes\" />\r\n", Xml(ipc["kServiceName"]), Xml(ipc["kServiceDisplayName"]));
                lines.AppendFormat("<ServiceControl Id=\"CredentialServiceControl\" Name=\"{0}\" Start=\"install\" Stop=\"both\" Remove=\"uninstall\" Wait=\"yes\" />\r\n", Xml(ipc["kServiceName"]));
            }
            lines.Append("</Component></DirectoryRef>\r\n");
        }
        lines.Append("<ComponentGroup Id=\"ProductPayload\">\r\n");
        foreach (string id in components) lines.AppendFormat("<ComponentRef Id=\"{0}\" />\r\n", id);
        lines.Append("</ComponentGroup></Fragment></Wix>\r\n");
        WriteIfDifferent(Path.Combine(BuildDirectory, "generated", "Payload.wxs"), lines.ToString());
    }

    void Validate()
    {
        PackagePath = Path.GetFullPath(PackagePath);
        Require(Path.GetFileName(PackagePath) == SetupFile, "MSI filename does not match product metadata.");
        using (var database = MsiDatabase.Open(PackagePath))
        {
            var properties = database.Rows("SELECT `Property`,`Value` FROM `Property`", 2).ToDictionary(r => r[0], r => r[1]);
            Require(properties["ProductVersion"] == ReleaseVersion && properties["FullProductVersion"] == ProductVersion && properties["ALLUSERS"] == "1", "MSI version or machine scope mismatch.");
            Require(database.Summary(7).Split(';')[0] == (Architecture == "x64" ? "x64" : "Arm64"), "Wrong MSI architecture.");
            var codes = HeaderStrings(Path.Combine(MsiDirectory, "MsiContract.h"));
            Require(String.Equals(properties["UpgradeCode"], codes[Architecture == "x64" ? "kX64UpgradeCode" : "kArm64UpgradeCode"], StringComparison.OrdinalIgnoreCase), "Wrong MSI product family.");
            Guid.Parse(properties["ProductCode"]);
            Guid.Parse(database.Summary(9));
            Require(!properties.ContainsKey("REINSTALLMODE"), "Do not override REINSTALLMODE in the package Property table.");
            Require(database.Rows("SELECT `Argument` FROM `ControlEvent` WHERE `Event`='ReinstallMode'", 1).Any(r => r[0].IndexOf('e') >= 0 && r[0].IndexOf('a') < 0), "Repair must replace equal-version files without forcing replacement of every file.");
            Require(database.Rows("SELECT `VersionMax`,`Attributes`,`ActionProperty` FROM `Upgrade`", 3).Any(r => r[2] == "WIX_UPGRADE_DETECTED" && r[0] == ReleaseVersion && (Int32.Parse(r[1]) & 512) != 0), "Same MSI version upgrade recognition is missing.");
            var media = database.Rows("SELECT `Cabinet` FROM `Media`", 1);
            Require(media.Count != 0 && media.All(r => r[0].StartsWith("#", StringComparison.Ordinal)), "MSI payload must use embedded cabinets.");
            var actions = database.Rows("SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`", 4).ToDictionary(r => r[0]);
            var ipc = HeaderStrings(Path.Combine(WindowsDirectory, "SavedCredential", "SavedCredentialIpc.h"));
            var controls = database.Rows("SELECT `Name`,`Event`,`Wait` FROM `ServiceControl`", 3).Where(r => r[0] == ipc["kServiceName"]).ToArray();
            Require(controls.Length == 1 && (Int32.Parse(controls[0][1]) & 0xa3) == 0xa3 && controls[0][2] == "1", "MSI must start, stop and remove the credential service, waiting for completion.");
            var sequence = database.Rows("SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`", 3).ToDictionary(r => r[0]);
            var uiSequence = database.Rows("SELECT `Action`,`Condition`,`Sequence` FROM `InstallUISequence`", 3).ToDictionary(r => r[0]);
            foreach (string table in new[] { "InstallUISequence", "InstallExecuteSequence" })
            {
                var rows = table == "InstallUISequence" ? uiSequence : sequence;
                Require(rows.ContainsKey("CheckExeInstallation") && Before(rows, "LaunchConditions", "CheckExeInstallation") && Before(rows, "CheckExeInstallation", "CostInitialize"), "EXE installation check must follow launch conditions before costing: " + table);
            }
            Require(sequence.ContainsKey("CloseApplication") && sequence.ContainsKey("InitializeDeployment") && sequence.ContainsKey("StartServices") && sequence.ContainsKey("CaptureRebootState") &&
                Before(sequence, "ValidateDeployment", "CloseApplication") && Before(sequence, "CloseApplication", "InstallValidate") &&
                Before(sequence, "InstallValidate", "InitializeDeployment") && Before(sequence, "InitializeDeployment", "InstallInitialize") &&
                Before(sequence, "InstallExecute", "RemoveExistingProducts") && Before(sequence, "RemoveExistingProducts", "InstallFinalize") &&
                Before(sequence, "InstallInitialize", "RollbackDeployment") && Before(sequence, "RollbackDeployment", "PrepareDeployment") &&
                Before(sequence, "PrepareDeployment", "StopServices") && sequence["InstallExecute"][1] == "1" &&
                Before(sequence, "StopServices", "InstallFiles") && Before(sequence, "InstallServices", "StartServices") &&
                Before(sequence, "RemoveExistingProducts", "StartServices") && Before(sequence, "StartServices", "CaptureRebootState") &&
                Before(sequence, "CaptureRebootState", "CompleteDeployment") && Before(sequence, "CompleteDeployment", "CommitDeployment") &&
                Before(sequence, "CommitDeployment", "InstallFinalize") && sequence["RemoveProductData"][1] == "REMOVE~=\"ALL\" AND NOT UPGRADINGPRODUCTCODE" &&
                Before(sequence, "StopServices", "RemoveProductData") && Before(sequence, "RemoveProductData", "DeleteServices") && Before(sequence, "RemoveProductData", "RemoveFiles"),
                "Unsafe MSI lifecycle action ordering or conditions.");
            foreach (string action in new[] { "PrepareDeployment", "CompleteDeployment", "RemoveProductData" })
                Require((Int32.Parse(actions[action][1]) & 0xc00) == 0xc00, "Native deferred action must run as installer server: " + action);
            var files = database.Rows("SELECT `File`,`FileName`,`Version`,`Component_`,`Language` FROM `File`", 5);
            var components = database.Rows("SELECT `Component`,`Directory_`,`Attributes` FROM `Component`", 3).ToDictionary(r => r[0]);
            var directories = database.Rows("SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`", 3).ToDictionary(r => r[0]);
            var identity = HeaderStrings(Path.Combine(WindowsDirectory, "ProductIdentity.h"));
            string[] root;
            Require(directories.TryGetValue("DesktopDirectory", out root) && root[1] == "ProgramFiles64Folder" && LongName(root[2].Split(':')[0]) == identity["kDesktopDirectoryName"], "Wrong MSI product installation directory.");
            var expected = GetPayload();
            Require(files.Count == expected.Count, "Unexpected MSI file count.");
            string scratch = Path.Combine(Path.GetTempPath(), "UnlockMsiCheck-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(scratch);
            try
            {
                int index = 0;
                foreach (var cabinet in media)
                {
                    string cab = Path.Combine(scratch, "payload" + index++ + ".cab");
                    database.Export("_Streams", cabinet[0].Substring(1), cab);
                    var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "expand.exe"), "-F:* \"" + cab + "\" \"" + scratch + "\"") { UseShellExecute = false, CreateNoWindow = true };
                    using (var process = Process.Start(start))
                    {
                        process.WaitForExit();
                        Require(process.ExitCode == 0, "MSI cabinet extraction failed.");
                    }
                }
                foreach (var entry in expected)
                {
                    string id = "F" + PayloadId(entry.Name), extracted = Path.Combine(scratch, id);
                    Require(File.Exists(extracted) && Hash(extracted) == Hash(entry.Path), "MSI cabinet payload mismatch: " + entry.Name);
                    var matches = files.Where(r => r[0] == id).ToArray();
                    Require(matches.Length == 1 && (!entry.Product || matches[0][2] == ProductVersion), "MSI file metadata mismatch: " + entry.Name);
                    var row = matches[0];
                    Require(row[4] == MsiDatabase.FileLanguage(entry.Path), "MSI file language differs from payload: " + entry.Name);
                    if (row[4].Length != 0)
                        foreach (string language in row[4].Split(','))
                        {
                            Require(Regex.IsMatch(language, @"\A[0-9]+\z"), "Invalid MSI file language: " + entry.Name);
                            int lcid = Int32.Parse(language);
                            if (lcid != 0) CultureInfo.GetCultureInfo(lcid);
                        }
                    var component = components[row[3]];
                    Require((Int32.Parse(component[2]) & 256) != 0, "Product files require native 64-bit components.");
                    string directoryId = component[1], relative = LongName(row[1]);
                    var visited = new HashSet<string>();
                    while (directoryId != "DesktopDirectory")
                    {
                        Require(visited.Add(directoryId) && directories.ContainsKey(directoryId), "Invalid MSI target directory chain.");
                        var directory = directories[directoryId];
                        relative = LongName(directory[2].Split(':')[0]) + "\\" + relative;
                        directoryId = directory[1];
                    }
                    Require(relative == entry.Name, "Unexpected MSI install path: " + entry.Name);
                }
                string nativeActions = Path.Combine(scratch, InstallerFile);
                database.Export("Binary", "NativeActions", nativeActions);
                CheckArchitecture(nativeActions, true);
                var info = FileVersionInfo.GetVersionInfo(nativeActions);
                Require(info.FileVersion == ProductVersion && info.ProductVersion == ProductVersion && Hash(nativeActions) == Hash(Path.Combine(BuildDirectory, InstallerFile)), "Embedded native MSI action architecture/version/content mismatch.");
            }
            finally
            {
                string resolved = Path.GetFullPath(scratch), tempRoot = Path.GetFullPath(Path.GetTempPath()).TrimEnd('\\') + "\\";
                Require(resolved.StartsWith(tempRoot, StringComparison.OrdinalIgnoreCase), "Unsafe MSI validation scratch path.");
                Directory.Delete(resolved, true);
            }
        }
        Log.LogMessage(MessageImportance.High, "Verified self-contained {0} MSI {1}.", Architecture, ProductVersion);
    }

    static string LongName(string value) { return value.Split('|').Last(); }
    static bool Before(Dictionary<string, string[]> sequence, string first, string second)
    {
        return Int32.Parse(sequence[first][2]) < Int32.Parse(sequence[second][2]);
    }

    // Read-only Windows Installer API access: no install, repair or administrative install.
    sealed class MsiDatabase : IDisposable
    {
        readonly uint handle;
        MsiDatabase(uint value) { handle = value; }
        public static MsiDatabase Open(string path)
        {
            uint value;
            Check(MsiOpenDatabase(path, IntPtr.Zero, out value));
            return new MsiDatabase(value);
        }
        public void Dispose() { Check(MsiCloseHandle(handle)); }
        static void Check(uint code)
        {
            if (code != 0) throw new System.ComponentModel.Win32Exception((int)code, "Windows Installer API failed: " + code);
        }
        uint View(string query)
        {
            uint view;
            Check(MsiDatabaseOpenView(handle, query, out view));
            try { Check(MsiViewExecute(view, 0)); return view; }
            catch { Check(MsiCloseHandle(view)); throw; }
        }
        static string Field(uint record, uint field)
        {
            uint length = 0;
            uint status = MsiRecordGetString(record, field, null, ref length);
            if (status != 234) Check(status);
            var text = new StringBuilder((int)length + 1);
            length++;
            Check(MsiRecordGetString(record, field, text, ref length));
            return text.ToString();
        }
        public List<string[]> Rows(string query, int columns)
        {
            uint view = View(query);
            try
            {
                var rows = new List<string[]>();
                for (;;)
                {
                    uint record;
                    uint status = MsiViewFetch(view, out record);
                    if (status == 259) return rows;
                    Check(status);
                    try
                    {
                        var row = new string[columns];
                        for (int i = 0; i < columns; ++i) row[i] = Field(record, (uint)i + 1);
                        rows.Add(row);
                    }
                    finally { Check(MsiCloseHandle(record)); }
                }
            }
            finally { Check(MsiCloseHandle(view)); }
        }
        public string Summary(uint property)
        {
            uint summary;
            Check(MsiGetSummaryInformation(handle, null, 0, out summary));
            try
            {
                uint type, length = 0;
                int number;
                System.Runtime.InteropServices.ComTypes.FILETIME time;
                uint status = MsiSummaryInfoGetProperty(summary, property, out type, out number, out time, null, ref length);
                if (status != 234) Check(status);
                var text = new StringBuilder((int)length + 1);
                length++;
                Check(MsiSummaryInfoGetProperty(summary, property, out type, out number, out time, text, ref length));
                return text.ToString();
            }
            finally { Check(MsiCloseHandle(summary)); }
        }
        public void Export(string table, string name, string path)
        {
            Require(table == "_Streams" || table == "Binary", "Invalid MSI stream table.");
            uint view = View("SELECT `Data` FROM `" + table + "` WHERE `Name`='" + name.Replace("'", "''") + "'");
            try
            {
                uint record;
                Check(MsiViewFetch(view, out record));
                try
                {
                    using (var stream = File.Create(path))
                    {
                        byte[] bytes = new byte[1048576];
                        for (;;)
                        {
                            uint length = (uint)bytes.Length;
                            Check(MsiRecordReadStream(record, 1, bytes, ref length));
                            if (length == 0) break;
                            stream.Write(bytes, 0, (int)length);
                        }
                    }
                }
                finally { Check(MsiCloseHandle(record)); }
            }
            finally { Check(MsiCloseHandle(view)); }
        }
        public static string FileLanguage(string path)
        {
            uint versionLength = 0, languageLength = 0;
            uint status = MsiGetFileVersion(path, null, ref versionLength, null, ref languageLength);
            // Non-versioned files have no File.Language value.
            if (status == 1006) return "";
            if (status != 234) Check(status);
            var version = new StringBuilder((int)versionLength + 1);
            var language = new StringBuilder((int)languageLength + 1);
            versionLength++; languageLength++;
            Check(MsiGetFileVersion(path, version, ref versionLength, language, ref languageLength));
            return language.ToString();
        }

        [DllImport("msi.dll", EntryPoint = "MsiOpenDatabaseW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiOpenDatabase(string path, IntPtr persist, out uint database);
        [DllImport("msi.dll", ExactSpelling = true)] static extern uint MsiCloseHandle(uint handle);
        [DllImport("msi.dll", EntryPoint = "MsiDatabaseOpenViewW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiDatabaseOpenView(uint database, string query, out uint view);
        [DllImport("msi.dll", ExactSpelling = true)] static extern uint MsiViewExecute(uint view, uint record);
        [DllImport("msi.dll", ExactSpelling = true)] static extern uint MsiViewFetch(uint view, out uint record);
        [DllImport("msi.dll", EntryPoint = "MsiRecordGetStringW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);
        [DllImport("msi.dll", ExactSpelling = true)] static extern uint MsiRecordReadStream(uint record, uint field, [Out] byte[] bytes, ref uint length);
        [DllImport("msi.dll", EntryPoint = "MsiGetSummaryInformationW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiGetSummaryInformation(uint database, string path, uint updateCount, out uint summary);
        [DllImport("msi.dll", EntryPoint = "MsiSummaryInfoGetPropertyW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiSummaryInfoGetProperty(uint summary, uint property, out uint type, out int number, out System.Runtime.InteropServices.ComTypes.FILETIME time, StringBuilder text, ref uint length);
        [DllImport("msi.dll", EntryPoint = "MsiGetFileVersionW", CharSet = CharSet.Unicode, ExactSpelling = true)] static extern uint MsiGetFileVersion(string path, StringBuilder version, ref uint versionLength, StringBuilder language, ref uint languageLength);
    }
}
