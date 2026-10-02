<!-- Created by Rui MA on 26 Sep 2026 -->

# PairingTool

`unlock_pairing_tool.exe` is the current Windows-side first-enrollment prototype. It receives the iPhone's raw P-256 public key as 130 hexadecimal characters, displays its SHA-256 fingerprint, and shows a Windows notification with explicit Confirm/Cancel buttons.

```powershell
.\windows\build\unlock_pairing_tool.exe --key-hex <130-hex-digit-public-key>
```

The iOS app can copy the raw public key to the clipboard. After copying it, the shorter Windows command avoids putting the key in shell history:

```powershell
.\windows\build\unlock_pairing_tool.exe --key-clipboard
```

The key is written only after Confirm is selected. It is stored at `%ProgramData%\UnlockWindowsWithIPhone\enrollment.dat`, protected with DPAPI machine scope and an ACL for SYSTEM, Administrators and the file owner. Use `--replace` for an intentional replacement:

```powershell
.\windows\build\unlock_pairing_tool.exe --key-hex <130-hex-digit-public-key> --replace
```

To remove the enrolled key, the tool requires typing `REMOVE`:

```powershell
.\windows\build\unlock_pairing_tool.exe --clear
```

This is a foreground prototype. It creates a per-user Start Menu shortcut with an AppUserModelID so the unpackaged desktop executable can use an interactive toast. If Windows accepts the toast but does not surface it, the tool falls back to a visible Yes/No confirmation dialog after a short timeout. The final installation should provide that identity through the packaged/installer deployment. The current GATT host does not pass enrollment data to this tool; copy the public key explicitly and confirm it on Windows.
