using System;
using System.IO;
using System.Text;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;

public sealed class UnlockBuildTask : Task
{
    [Required] public string Operation { get; set; }
    [Required] public string WindowsDirectory { get; set; }
    [Required] public string ProductVersion { get; set; }
    public string Architecture { get; set; }
    public string VersionDefinition { get; set; }
    public string OutputFile { get; set; }
    public string OriginalFilename { get; set; }
    public string ResourceType { get; set; }

    public override bool Execute()
    {
        try
        {
            var version = Version.Parse(ProductVersion);
            if (version.Major > 255 || version.Minor > 255 || version.Build < 0 ||
                version.Build > 65535 || version.Revision < 0 || version.Revision > 65535)
                throw new InvalidOperationException("Invalid four-part product version or MSI version range.");
            if (Architecture != "x64" && Architecture != "arm64")
                throw new InvalidOperationException("Only x64 and ARM64 builds are supported.");
            if (Operation == "Validate") return true;
            if (Operation == "CheckIncrement" || Operation == "Advance")
            {
                if (version.Revision == 65535)
                    throw new InvalidOperationException("Product build number is 65535. Set the next release/build in ProductVersion.h.");
                if (Operation == "CheckIncrement") return true;
                string path = Path.Combine(WindowsDirectory, "ProductVersion.h");
                string header = File.ReadAllText(path);
                if (String.IsNullOrEmpty(VersionDefinition) || !header.Contains(VersionDefinition))
                    throw new InvalidOperationException("ProductVersion.h changed during the build; build number was not advanced.");
                string next = String.Format("kProductVersion{{{0}, {1}, {2}, {3}}}", version.Major, version.Minor, version.Build, version.Revision + 1);
                File.WriteAllText(path, header.Replace(VersionDefinition, next), new UTF8Encoding(false));
                Log.LogMessage(MessageImportance.High, "Built {0}. Next local build: {1}.{2}.{3}.{4}.",
                    ProductVersion, version.Major, version.Minor, version.Build, version.Revision + 1);
                return true;
            }
            if (Operation != "Resource") throw new InvalidOperationException("Unknown build task operation: " + Operation);
            string numbers = ProductVersion.Replace('.', ',');
            string resourceHeader = Path.GetFullPath(Path.Combine(WindowsDirectory, "Resources", "resource.h")).Replace('\\', '/');
            string content = String.Join("\r\n", new[] {
                "// Generated from ProductVersion.h; do not edit.", "#include <windows.h>", "#include \"" + resourceHeader + "\"",
                "1 VERSIONINFO", "FILEVERSION " + numbers, "PRODUCTVERSION " + numbers,
                "FILEFLAGSMASK VS_FFI_FILEFLAGSMASK", "FILEFLAGS 0", "FILEOS VOS_NT_WINDOWS32", "FILETYPE " + ResourceType,
                "FILESUBTYPE 0", "BEGIN", "    BLOCK \"StringFileInfo\"", "    BEGIN", "        BLOCK \"040904b0\"", "        BEGIN",
                "            VALUE \"CompanyName\", \"Rui MA\\0\"", "            VALUE \"FileDescription\", UNLOCK_PRODUCT_NAME",
                "            VALUE \"FileVersion\", \"" + ProductVersion + "\\0\"",
                "            VALUE \"ProductVersion\", \"" + ProductVersion + "\\0\"",
                "            VALUE \"ProductName\", UNLOCK_PRODUCT_NAME",
                "            VALUE \"OriginalFilename\", \"" + OriginalFilename + "\\0\"",
                "        END", "    END", "    BLOCK \"VarFileInfo\"", "    BEGIN", "        VALUE \"Translation\", 0x0409, 1200", "    END", "END", ""
            });
            Directory.CreateDirectory(Path.GetDirectoryName(OutputFile));
            if (!File.Exists(OutputFile) || File.ReadAllText(OutputFile) != content)
                File.WriteAllText(OutputFile, content, new UTF8Encoding(false));
            return true;
        }
        catch (Exception error) { Log.LogErrorFromException(error, true); return false; }
    }
}
