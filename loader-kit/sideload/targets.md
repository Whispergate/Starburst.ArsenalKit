# DLL Sideloading Targets

Known signed Windows binaries vulnerable to DLL sideloading. These binaries
load DLLs from their own directory before searching System32, allowing a
proxy DLL placed alongside them to be loaded instead.

## Selection Criteria

A good sideloading target should be:

- Digitally signed by a trusted publisher (Microsoft, Adobe, etc.)
- Present on many systems or easily deployed
- Load a DLL with few exports (easier to proxy)
- Not monitored by EDR as a known sideloading vector

---

## Target List

### Microsoft Binaries

| Binary | DLL Loaded | Typical Path | Signed By | Notes |
|--------|-----------|--------------|-----------|-------|
| `OneDrive.exe` | `version.dll` | `%LOCALAPPDATA%\Microsoft\OneDrive\` | Microsoft | Auto-starts, good for persistence. Runs in user context. |
| `Teams.exe` (classic) | `version.dll` | `%LOCALAPPDATA%\Microsoft\Teams\current\` | Microsoft | Very common on enterprise systems. User context. |
| `MicrosoftEdgeUpdate.exe` | `msedge.dll` | `%PROGRAMFILES(X86)%\Microsoft\EdgeUpdate\` | Microsoft | Runs periodically via scheduled task. |
| `SearchProtocolHost.exe` | `mso.dll` | `%PROGRAMFILES%\Microsoft Office\root\Office16\` | Microsoft | Part of Windows Search indexer. |
| `MsMpEng.exe` | `mpsvc.dll` | `%PROGRAMFILES%\Windows Defender\` | Microsoft | Defender engine. Requires admin to write to dir. Known vector (REvil). |
| `ComputerDefaults.exe` | `propsys.dll` | `C:\Windows\System32\` | Microsoft | Auto-elevate binary. Can bypass UAC. |
| `fodhelper.exe` | `propsys.dll` | `C:\Windows\System32\` | Microsoft | Auto-elevate binary. UAC bypass vector. |
| `computerdefaults.exe` | `profapi.dll` | `C:\Windows\System32\` | Microsoft | Alternate DLL for auto-elevation. |
| `SystemSettingsAdminFlows.exe` | `propsys.dll` | `C:\Windows\System32\` | Microsoft | Auto-elevate binary. |
| `sysprep.exe` | `dbgcore.dll` | `C:\Windows\System32\Sysprep\` | Microsoft | Legitimate sysadmin tool. Writable dir for some configs. |
| `WSReset.exe` | `propsys.dll` | `C:\Windows\System32\` | Microsoft | Windows Store reset. Auto-elevate. UAC bypass. |

### Third-Party Applications

| Binary | DLL Loaded | Typical Path | Signed By | Notes |
|--------|-----------|--------------|-----------|-------|
| `Notepad++.exe` | `SciLexer.dll` | `%PROGRAMFILES%\Notepad++\` | Notepad++ | Very common. SciLexer is large, many exports. |
| `GUP.exe` | `libcurl.dll` | `%PROGRAMFILES%\Notepad++\updater\` | Notepad++ | Notepad++ updater. Fewer exports than SciLexer. |
| `KeePass.exe` | `version.dll` | `%PROGRAMFILES%\KeePass\` | KeePass | Password manager. Sensitive target. |
| `vlc.exe` | `libvlc.dll` | `%PROGRAMFILES%\VideoLAN\VLC\` | VideoLAN | Common media player. Many exports. |
| `Taskmgr.exe` | `SRClient.dll` | `C:\Windows\System32\` | Microsoft | Task Manager. May require elevated write. |
| `WinSCP.exe` | `DragExt.dll` | `%PROGRAMFILES%\WinSCP\` | WinSCP | SCP/SFTP client. Common on admin systems. |
| `putty.exe` | `WINMM.dll` | Various | PuTTY | SSH client. Often placed in writable directories. |
| `7zFM.exe` | `7z.dll` | `%PROGRAMFILES%\7-Zip\` | 7-Zip | File archiver. Many exports. |

### Browsers

| Binary | DLL Loaded | Typical Path | Signed By | Notes |
|--------|-----------|--------------|-----------|-------|
| `chrome.exe` | `chrome_elf.dll` | `%PROGRAMFILES%\Google\Chrome\Application\` | Google | Complex DLL, many exports. Harder to proxy. |
| `msedge.exe` | `msedge_elf.dll` | `%PROGRAMFILES(X86)%\Microsoft\Edge\Application\` | Microsoft | Similar complexity to Chrome. |

---

## Categorized by Use Case

### Persistence (auto-start applications)

These binaries start automatically or run periodically, making them
suitable for persistence mechanisms:

| Binary | Trigger |
|--------|---------|
| `OneDrive.exe` | User logon (Run key) |
| `Teams.exe` | User logon (Run key) |
| `MicrosoftEdgeUpdate.exe` | Scheduled task (every few hours) |

Place the proxy DLL in the application's directory. When the application
starts (on logon or schedule), it will load your proxy DLL automatically.

### UAC Bypass (auto-elevate binaries)

These binaries have auto-elevate manifests, meaning they run elevated
without showing a UAC prompt. Sideloading into these gives you elevated
execution:

| Binary | DLL | Technique |
|--------|-----|-----------|
| `ComputerDefaults.exe` | `propsys.dll` | Copy binary + DLL to writable dir, run |
| `fodhelper.exe` | `propsys.dll` | Registry-based, no DLL copy needed |
| `WSReset.exe` | `propsys.dll` | Copy binary + DLL to writable dir, run |
| `sysprep.exe` | `dbgcore.dll` | Writable Sysprep directory |

Note: Most auto-elevate binaries require the binary itself to be in a
trusted location. The technique typically involves modifying registry keys
that the auto-elevate binary reads, rather than placing a DLL next to it.

### Execution Only (run payload once)

Any sideloading target works for one-time execution. Prefer targets with
fewer exports (easier to proxy) and that are commonly found on systems:

- `version.dll` proxying is simplest (17 exports)
- `winmm.dll` is another easy target (~180 exports, but many can be stubbed)
- `dbghelp.dll` is moderate (~200 exports)

---

## How to Enumerate Exports

To create a proxy DLL for a new target, first enumerate the real DLL's
exports:

```cmd
:: Windows (Visual Studio)
dumpbin /exports C:\Windows\System32\version.dll

:: Cross-platform (MinGW)
x86_64-w64-mingw32-objdump -p /path/to/version.dll | grep -A 999 "Export Table"

:: Python (pefile)
python -c "import pefile; pe = pefile.PE('version.dll'); [print(e.name.decode()) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]"
```

Then generate `#pragma comment(linker, "/export:...")` directives for each
export. See `sideload_template.c` for the format.

---

## EDR Considerations

Known sideloading vectors that EDRs actively monitor:

- `MsMpEng.exe` + `mpsvc.dll` (used by REvil ransomware)
- `Teams.exe` + `version.dll` (heavily abused, now commonly flagged)
- `ComputerDefaults.exe` / `fodhelper.exe` (well-known UAC bypass)

Less-monitored vectors:

- `GUP.exe` + `libcurl.dll` (Notepad++ updater)
- `WinSCP.exe` + `DragExt.dll`
- `OneDrive.exe` in non-default install paths
- Obscure Microsoft Office sub-binaries

Always test against the specific EDR deployed in your target environment.
Detection signatures change frequently.
