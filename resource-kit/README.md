# Starburst Arsenal Kit - Resource Kit

Delivery stagers for loading and executing Starburst shellcode (.bin) payloads.

## Stager Index

| File | Language | Technique | OPSEC Rating | Use Case |
|------|----------|-----------|--------------|----------|
| `powershell/stager_valloc.ps1` | PowerShell | VirtualAlloc + CreateThread | Low | Quick testing, lab environments |
| `powershell/stager_delegate.ps1` | PowerShell | Delegate invoke (no CreateThread) | Medium | Avoids CreateThread monitoring |
| `powershell/cradle_download.ps1` | PowerShell | Download + in-memory exec | Medium | Staged delivery, nothing on disk |
| `powershell/cradle_staged.ps1` | PowerShell | Download + AES decrypt + exec | High | Encrypted staged delivery |
| `hta/template_exec.hta` | VBScript/HTA | Drop and execute | Low | Initial access via phishing |
| `hta/template_psh.hta` | VBScript/HTA | Launch hidden PowerShell | Low-Medium | Initial access, browser delivery |
| `vbs/stager.vbs` | VBScript | COM object execution chains | Low-Medium | Phishing attachments, macro alternative |
| `python/stager_ctypes.py` | Python | ctypes VirtualAlloc local | Medium | Targets with Python installed |
| `python/stager_inject.py` | Python | ctypes remote process injection | Medium | Cross-process injection |
| `csharp/Loader.cs` | C# | P/Invoke VirtualAlloc + CreateThread | Low-Medium | .NET environments, compilable on target |
| `csharp/SectionLoader.cs` | C# | NtCreateSection + NtMapViewOfSection | High | Avoids VirtualAlloc, stealthier allocation |
| `csharp/DInvoke.cs` | C# | D/Invoke manual syscalls | Very High | Bypasses user-mode API hooks |
| `msbuild/inline_task.xml` | C#/XML | MSBuild inline task | High | Application whitelisting bypass |

## General OPSEC Considerations

- **Memory allocation**: RWX memory pages are a strong indicator. All stagers in this kit use RW allocation followed by a flip to RX after shellcode is copied.
- **API call sequences**: VirtualAlloc -> memcpy -> CreateThread is a well-known pattern. Consider using section mapping (SectionLoader.cs) or syscalls (DInvoke.cs) for better evasion.
- **PowerShell**: AMSI will inspect scripts. Consider AMSI bypass or obfuscation before deployment. PowerShell ScriptBlock logging and module logging will capture execution.
- **Process creation**: HTA and VBS stagers that spawn child processes (powershell.exe, cmd.exe) create parent-child relationships that EDR monitors.
- **Network indicators**: Download cradles create network connections. Use HTTPS, domain fronting, or redirectors to obscure C2 infrastructure.
- **On-disk artifacts**: Prefer in-memory execution. If dropping to disk is required, use encrypted payloads and clean up after execution.

## Quick Start

1. Generate Starburst shellcode (.bin) from the Mythic payload builder
2. Choose a stager appropriate for your delivery scenario
3. Replace placeholder values (shellcode path, URLs, keys) with your operational values
4. Test in a lab environment before operational deployment

## Compilation Notes

### C# Loaders
```
csc /unsafe /out:loader.exe Loader.cs
csc /unsafe /out:sectionloader.exe SectionLoader.cs
csc /unsafe /out:dinvoke.exe DInvoke.cs
```

### MSBuild Execution
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe inline_task.xml
```

### Python
```
python stager_ctypes.py shellcode.bin
python stager_inject.py shellcode.bin <PID>
```
