# OPSEC Considerations

Detection surfaces, indicators, and operational guidance for each Arsenal Kit component.

---

## Detection Surface by Kit Component

### Sleep Mask Kit

| Indicator | Detail | Detection Risk |
|-----------|--------|----------------|
| **Stack frames** | Synthetic frames lack valid unwind chains beyond the spoofed depth | Medium -- deep stack walkers (e.g., ETW stack walks beyond `SPOOF_MAX_FRAMES`) can detect truncation |
| **Gadget scanning** | Draugr scans KernelBase.dll for `JMP [RBX]` gadgets at init time | Low -- done once, but the scan pattern itself may be flagged by in-memory scanners |
| **Timer objects** | Sleep via `NtSetTimer`/`WaitForSingleObject` creates kernel timer objects | Low -- timer usage is normal, but high-frequency timer creation from unbacked memory is unusual |
| **Memory protection flipping** | Encrypt (RW) -> sleep -> decrypt (RX) cycle during sleep masking | Medium -- protection flipping on private memory is a known indicator for some EDR vendors |

**Recommendations:**
- Use the `SPOOF_PROFILE_CUSTOM` slot to match a real stack on the target system -- generic profiles are fingerprinted
- Rebuild profiles per engagement target (Windows build + patch level specific)
- Prefer the function+offset format over module RVA for portability across patch levels

### Artifact Kit

| Indicator | Detail | Detection Risk |
|-----------|--------|----------------|
| **PE metadata** | Default resource.rc has placeholder values | High -- mismatched or absent version info on a "legitimate" binary is a red flag |
| **Compile timestamps** | MinGW/MSVC embed timestamps in PE header and Rich header | High -- future/zero timestamps are a known indicator |
| **Import table** | `VirtualAlloc`, `VirtualProtect`, `CreateThread` in IAT | Medium -- standard for many apps but flagged in combination |
| **Section names** | Non-standard section names (`.text0`, custom names) | Medium -- some tools flag unusual section names |
| **Entropy** | Encrypted/compressed shellcode blob has high entropy | Medium -- high entropy sections are a static scanning indicator |
| **Digital signature** | Unsigned binary in a location where signed binaries are expected | High -- catalog/Authenticode checks are standard |

**Recommendations:**
- Always customize `resource.rc` to match a legitimate application on the target
- Use the `-fno-ident` flag to remove compiler identification strings
- Prefer bypass techniques that avoid RWX memory (pipe bypass, fiber bypass)

### Injection Kit

| Indicator | Detail | Detection Risk |
|-----------|--------|----------------|
| **Cross-process handle** | `OpenProcess(PROCESS_ALL_ACCESS)` on a remote process | High -- EDR hooks `NtOpenProcess` and flags full access requests |
| **Remote allocation** | `VirtualAllocEx` in a remote process | High -- primary indicator for remote injection |
| **Remote write** | `WriteProcessMemory` into allocated region | High -- almost always flagged alongside remote allocation |
| **Remote thread** | `CreateRemoteThread` or `NtCreateThreadEx` | High -- most EDR vendors hook this aggressively |
| **Protection change** | `VirtualProtectEx(PAGE_EXECUTE_READ)` on remote memory | Medium -- the RW->RX transition is a known pattern |
| **ETW events** | Thread creation generates ETW `THREAD_START` events with start address in private memory | High -- ETW-based detections check start address backing |

**Recommendations:**
- Default `CreateRemoteThread` in `cmd_shinject.cc` is the most detected injection method -- swap it
- Consider section-based injection (`NtCreateSection` + `NtMapViewOfSection`) for shared memory without `WriteProcessMemory`
- Use `NtCreateThreadEx` with `THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER` cautiously -- some EDR flag this flag itself
- Prefer self-injection (current process) over cross-process injection when the mission allows it

### Resource Kit

| Indicator | Detail | Detection Risk |
|-----------|--------|----------------|
| **PowerShell** | `System.Runtime.InteropServices.Marshal`, `VirtualAlloc`, `DelegateType` | High -- AMSI scans PowerShell content in-memory |
| **C# / .NET** | P/Invoke of `VirtualAlloc`, `NtCreateSection`, unsafe code | Medium -- .NET assemblies are inspectable via metadata |
| **HTA** | `mshta.exe` process creation, ActiveX scripting | High -- `mshta.exe` execution is heavily monitored |
| **VBScript** | `wscript.exe` / `cscript.exe` with suspicious content | High -- script host execution is baseline-monitored |
| **Python** | `ctypes.windll` calls to kernel32 | Low-Medium -- less monitored but increasingly flagged |
| **Download cradle** | Network request to retrieve staged payload | Medium -- URL reputation, SSL inspection, content scanning |

**Recommendations:**
- PowerShell stagers should use AMSI bypass before loading shellcode
- Base64-only encoding is insufficient -- use XOR or AES encryption with a runtime key
- Avoid `Invoke-Expression` (IEX) and `DownloadString` -- these are primary alerting keywords
- C# stagers should use `System.Reflection` loading from memory rather than disk-dropped assemblies

### Loader Kit

| Indicator | Detail | Detection Risk |
|-----------|--------|----------------|
| **Module stomping** | Legitimate DLL mapped, then `.text` section overwritten | Medium -- memory scan shows module-backed memory with content that does not match the on-disk file |
| **Sideloading** | DLL loaded from application directory instead of System32 | Medium -- DLL load path anomaly detection (e.g., DLL loaded from `C:\Users\` instead of `C:\Windows\`) |
| **Proxy forwards** | `.def` file with absolute path forwards to System32 | Low -- forwarded exports are legitimate PE features |
| **DllMain execution** | Shellcode runs during `DLL_PROCESS_ATTACH` | Low -- DllMain execution is normal, but long-running DllMain or thread creation from DllMain is suspicious |

**Recommendations:**
- For module stomping, choose a DLL whose real `.text` content you are unlikely to be compared against
- For sideloading, use applications that legitimately load DLLs from their own directory (do not create artificial load-order hijacking)
- Consider delayed execution -- do not execute shellcode immediately in `DLL_PROCESS_ATTACH`; use a timer or wait for a specific event

---

## ETW Events by Technique

Event Tracing for Windows is the primary telemetry source for EDR. Key events triggered by kit components:

| ETW Provider | Event | Triggered By | Kit Component |
|-------------|-------|-------------|---------------|
| `Microsoft-Windows-Kernel-Process` | Process/Thread Create | `CreateRemoteThread`, `NtCreateThreadEx` | Injection Kit |
| `Microsoft-Windows-Kernel-Memory` | VirtualAlloc | `VirtualAllocEx` (remote), `VirtualAlloc` (local) | Injection Kit, Artifact Kit |
| `Microsoft-Windows-Kernel-Memory` | ProtectVM | `VirtualProtect`, `VirtualProtectEx` | All kits (RW->RX) |
| `Microsoft-Windows-DotNETRuntime` | Assembly Load | .NET assembly loading | Resource Kit (C#) |
| `Microsoft-Windows-PowerShell` | Script Block Logging | PowerShell execution | Resource Kit (PS1) |
| `Microsoft-Windows-AMSI` | AMSI Scan | Script content inspection | Resource Kit (PS1, VBS, HTA) |
| `Microsoft-Windows-Kernel-Audit` | Image Load | `LoadLibrary` for stomping/sideloading | Loader Kit |
| `Microsoft-Windows-Threat-Intelligence` | Memory allocation/protection | Kernel-level memory operations | All kits |

The `Microsoft-Windows-Threat-Intelligence` provider is particularly dangerous -- it operates at kernel level and cannot be unhooked from usermode. It feeds data to PPL-protected EDR processes. The only reliable way to avoid it is to not trigger the operations it monitors.

---

## Memory Indicators

### RWX Memory

**What triggers it:** Allocating memory with `PAGE_EXECUTE_READWRITE` in a single call.

**Detection:** Almost all EDR vendors flag RWX private memory. Some scan it immediately.

**Mitigation:** All Arsenal Kit components should use the two-step pattern:
1. `VirtualAlloc(..., PAGE_READWRITE)` -- allocate + write
2. `VirtualProtect(..., PAGE_EXECUTE_READ)` -- flip to executable after writing

The artifact bypass templates already follow this pattern. Verify any custom bypass does the same.

### Unbacked Executable Memory

**What triggers it:** Executable memory that is not backed by a file on disk (private, not image-mapped).

**Detection:** Thread start address or return address pointing to private (non-image) memory is the top indicator for in-memory payloads. Tools: `!address` in WinDbg, `MemProcFS`, Moneta.

**Mitigation:**
- **Module stomping** (Loader Kit) maps the agent over a legitimate DLL, making the memory appear image-backed
- **Phantom DLL hollowing** extends this by mapping a DLL from a transacted file that is never committed
- Use the Loader Kit over the Artifact Kit when operating against memory-scanning EDR

### Private Memory with Suspicious Protections

**What triggers it:** Large `PAGE_EXECUTE_READ` private regions, especially those were previously `PAGE_READWRITE`.

**Detection:** Memory protection transition logging via ETW `ProtectVM` events. Some EDR snapshot memory maps on suspicious events and compare.

**Mitigation:**
- Keep payload size small (sleep mask RX region should be minimal)
- Module stomping avoids this entirely since the memory is image-backed
- Consider `PAGE_EXECUTE` (without READ) if the code does not need to read its own memory (rare but reduces the indicator)

---

## Network Indicators

### Download Cradles

| Cradle Type | Indicators | Mitigation |
|------------|------------|------------|
| PowerShell `IEX(IWR ...)` | User-Agent: "Mozilla/5.0 (Windows NT; ... PowerShell/...)" | Custom User-Agent via `-UserAgent` parameter |
| PowerShell `Net.WebClient` | User-Agent: "Mozilla/4.0 (compatible; Win32; ...)" | Set `$wc.Headers.Add("User-Agent", ...)` |
| certutil | Command line logged, `certutil.exe` process creation | Avoid -- heavily signatured |
| bitsadmin | BITS transfer event in Event Log | Avoid -- logged and alertable |
| curl/wget | User-Agent header identifies tool | Acceptable with custom User-Agent |
| C# WebClient | Default .NET User-Agent | Set `Headers["User-Agent"]` |

### Staged Payloads

When hosting payloads for download:

- Use HTTPS with a valid certificate (not self-signed)
- Use a domain with established reputation (aged domain or domain fronting)
- Set appropriate `Content-Type` headers (do not serve `.bin` as `application/octet-stream` from a "news" site)
- Implement access controls (one-time download tokens, IP whitelisting, time-based expiry)
- Remove staged payloads immediately after delivery

---

## EDR Vendor Considerations

General guidance -- specific detections change with each EDR update:

| Vendor Category | Primary Detection Method | Key Concern for Arsenal Kit |
|----------------|--------------------------|---------------------------|
| **Kernel-callback EDR** (CrowdStrike, SentinelOne) | Kernel callbacks + ETW-TI | Remote injection APIs are caught at kernel level; usermode unhooking does not help |
| **Usermode-hook EDR** (older products, some NGAV) | `ntdll.dll` inline hooks | Can be bypassed via direct syscalls (Starburst uses Stardust syscall stubs), but hook presence itself is detectable |
| **Memory-scanning EDR** (Elastic, Defender ATP) | Periodic memory scanning + AMSI | Module stomping and sleep masking are critical; plaintext shellcode in memory will be caught |
| **Behavioral EDR** (all modern products) | Process/thread creation patterns, API call sequences | The sequence `OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread` is the canonical injection signature regardless of hook status |

**General guidance:**
- Against kernel-callback EDR: prefer self-injection or sideloading over remote injection
- Against memory-scanning EDR: always use sleep masking and prefer module stomping
- Against behavioral EDR: avoid the canonical injection API sequence; use section-based or callback-based techniques
- Test your specific payload against the target EDR in a lab before deploying

---

## Artifact Sanitization Checklist

Run through this checklist before deploying any compiled artifact:

### 1. PE Timestamps

```bash
# Check compile timestamp
python -c "
import pefile, sys, datetime
pe = pefile.PE(sys.argv[1])
ts = pe.FILE_HEADER.TimeDateStamp
print(f'Compile time: {datetime.datetime.utcfromtimestamp(ts)} UTC')
print(f'Raw value: 0x{ts:08x}')
" artifact.exe

# Zero the timestamp (post-build)
python -c "
import pefile, sys
pe = pefile.PE(sys.argv[1])
pe.FILE_HEADER.TimeDateStamp = 0
pe.write(sys.argv[1])
print('Timestamp zeroed')
" artifact.exe
```

Alternatively, compile with `-Wl,--no-insert-timestamp` (MinGW) to avoid timestamps at build time.

### 2. PDB Paths

```bash
# Check for embedded PDB path
strings artifact.exe | grep -i ".pdb"
# or
dumpbin /headers artifact.exe | findstr "pdb"

# PDB paths leak: username, directory structure, project names
# BAD:  C:\Users\operator\Desktop\starburst\build\starburst.pdb
# OK:   (no PDB path -- build with -s or /DEBUG:NONE)
```

MinGW: compile with `-s` (strip) to remove debug info entirely.
MSVC: do not use `/Zi` or `/DEBUG` for release builds.

### 3. Rich Header

The Rich header is an undocumented MSVC artifact that encodes compiler version, linker version, and build environment details. It is **only present in MSVC-compiled binaries** (MinGW does not generate it).

```bash
# Check for Rich header
python -c "
import sys
data = open(sys.argv[1], 'rb').read()
idx = data.find(b'Rich')
if idx > 0:
    print(f'Rich header found at offset 0x{idx:x}')
    print('Contains: MSVC version, linker version, build tool IDs')
else:
    print('No Rich header (MinGW build or already stripped)')
" artifact.exe

# Strip Rich header
python -c "
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
rich = data.find(b'Rich')
if rich > 0:
    # Find DanS marker (XOR'd, key is 4 bytes after Rich)
    key = int.from_bytes(data[rich+4:rich+8], 'little')
    dans = rich
    while dans > 0:
        dans -= 4
        val = int.from_bytes(data[dans:dans+4], 'little') ^ key
        if val == 0x536e6144:  # DanS
            break
    # Zero it out
    data[dans:rich+8] = b'\x00' * (rich + 8 - dans)
    open(sys.argv[1], 'wb').write(data)
    print(f'Rich header zeroed ({rich + 8 - dans} bytes)')
" artifact.exe
```

### 4. Version Info / Metadata

```bash
# Dump version info
python -c "
import pefile, sys
pe = pefile.PE(sys.argv[1])
if hasattr(pe, 'VS_FIXEDFILEINFO'):
    for entry in pe.FileInfo:
        for st in entry:
            for item in st.entries:
                for k, v in item.items():
                    print(f'{k}: {v}')
" artifact.exe
```

Ensure all version info fields match a legitimate application. Cross-reference against the real binary you are impersonating using `sigcheck` (Sysinternals) or `exiftool`.

### 5. Strings

```bash
# Scan for operational strings that should not be present
strings artifact.exe | grep -iE "(starburst|mythic|c2|beacon|implant|payload|hack|exploit)"

# Check for IP addresses / URLs
strings artifact.exe | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}"
strings artifact.exe | grep -oE "https?://[^ ]+"
```

Starburst's `symbol<>` template encrypts strings at compile time, but the Artifact Kit wrappers are standalone C -- verify no plaintext operational strings remain.

### 6. Section Characteristics

```bash
# Check section flags
dumpbin /headers artifact.exe | findstr "Section\|Characteristics"

# Verify:
# - .text is Execute + Read (not Execute + Read + Write)
# - No RWX sections
# - Section names are standard (.text, .rdata, .data, .rsrc)
```

### Complete Sanitization Script

```bash
#!/bin/bash
# sanitize.sh -- post-build artifact sanitization
# Usage: ./sanitize.sh artifact.exe

ARTIFACT="$1"

echo "[*] Sanitizing $ARTIFACT"

# Strip symbols and debug info
x86_64-w64-mingw32-strip --strip-all "$ARTIFACT"
echo "[+] Symbols stripped"

# Zero PE timestamp
python3 -c "
import pefile
pe = pefile.PE('$ARTIFACT')
pe.FILE_HEADER.TimeDateStamp = 0
pe.OPTIONAL_HEADER.CheckSum = 0
pe.write('$ARTIFACT')
" 2>/dev/null && echo "[+] Timestamps zeroed" || echo "[-] pefile not available, skip timestamp"

# Check for PDB paths
if strings "$ARTIFACT" | grep -qi ".pdb"; then
    echo "[!] WARNING: PDB path found in binary"
    strings "$ARTIFACT" | grep -i ".pdb"
fi

# Check for suspicious strings
SUSPICIOUS=$(strings "$ARTIFACT" | grep -ciE "(starburst|mythic|beacon|implant|cobalt)")
if [ "$SUSPICIOUS" -gt 0 ]; then
    echo "[!] WARNING: $SUSPICIOUS suspicious strings found"
fi

echo "[*] Final size: $(stat -f%z "$ARTIFACT" 2>/dev/null || stat -c%s "$ARTIFACT") bytes"
echo "[*] SHA256: $(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
echo "[+] Sanitization complete"
```

---

## Operational Workflow

### Pre-Engagement (Lab Testing)

```
1. Build payload with target-specific configuration
   - Custom spoof profile matching target OS build
   - Appropriate injection technique for target EDR
   - Artifact wrapper with matching metadata

2. Test against target EDR in lab
   - Deploy to VM with target EDR agent installed
   - Verify: no alerts on execution
   - Verify: no alerts during sleep cycle
   - Verify: no alerts during tasking (cmd exec, file ops)
   - Test all stager types you plan to use

3. Iterate until clean
   - Swap techniques if detected
   - Adjust sleep mask profile
   - Modify artifact wrapper metadata
```

### Pre-Deployment (Sanitization)

```
1. Build release payload (no debug flags, optimized)
2. Run sanitization checklist (timestamps, PDB, Rich header, strings)
3. Verify file hash does not match any known sample
4. Test sanitized artifact in lab one final time
5. Stage for delivery
```

### Deployment

```
1. Deliver via chosen method (resource kit stager, sideloading, etc.)
2. Confirm callback in Mythic
3. Remove staged payloads from hosting infrastructure
4. Delete local build artifacts from operator machine
5. Monitor for detection indicators in target environment
```

### Post-Engagement (Cleanup)

```
1. Rotate all cryptographic material (XOR keys, AES keys)
2. Rebuild spoof profiles (do not reuse across engagements)
3. Change artifact metadata (version info, icons)
4. Regenerate sideloading proxy DLLs with fresh timestamps
5. Archive engagement-specific builds separately
```
