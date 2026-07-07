# Starburst Arsenal Kit - Injection Techniques

Reference implementations of process injection techniques for adapting into Starburst's PIC codebase (cmd_shinject.cc / cmd_migrate.cc).

Each file is a standalone, compilable C implementation with detailed OPSEC commentary.

## Technique Comparison

| Technique | File | OPSEC | Key API Calls | New Thread? | Memory Type | ETW Events |
|---|---|---|---|---|---|---|
| CreateRemoteThread | `inject_crt.c` | LOW | OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, CreateRemoteThread | Yes (remote) | Private | TiVirtualAlloc, TiWriteVirtualMemory, TiProtectVirtualMemory, PsCreateThread |
| Early Bird APC | `inject_apc.c` | MEDIUM | CreateProcess(SUSPENDED), VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, QueueUserAPC, ResumeThread | No (APC on existing) | Private | TiVirtualAlloc, TiWriteVirtualMemory, TiQueueUserApc |
| Section Mapping | `inject_section.c` | MEDIUM-HIGH | NtCreateSection, NtMapViewOfSection (local RW), NtUnmapViewOfSection, NtMapViewOfSection (remote RX), NtCreateThreadEx | Yes (remote) | Section-backed | TiMapViewOfSection, PsCreateThread |
| Module Stomping | `inject_stomp.c` | HIGH | OpenProcess, CreateRemoteThread(LoadLibrary), WriteProcessMemory(.text), VirtualProtectEx, CreateRemoteThread | Yes (remote, x2) | Image-backed | TiWriteVirtualMemory, PsLoadImage, PsCreateThread |
| Thread Hijack | `inject_threadhijack.c` | MEDIUM-HIGH | OpenProcess, OpenThread, SuspendThread, GetThreadContext, SetThreadContext, VirtualAllocEx, WriteProcessMemory, ResumeThread | No | Private | TiGetSetContextThread, TiVirtualAlloc, TiWriteVirtualMemory |

## Detailed Pros/Cons

### CreateRemoteThread (inject_crt.c) - BASELINE
- **Pros**: Simple, reliable, works everywhere
- **Cons**: Every EDR detects this; CreateRemoteThread is the #1 injection indicator; thread starts from unbacked memory

### Early Bird APC (inject_apc.c)
- **Pros**: No CreateRemoteThread; APC fires before target code runs; clean process context
- **Cons**: Suspended process creation is suspicious; still uses VirtualAllocEx/WriteProcessMemory; some EDRs now flag APC patterns

### Section Mapping (inject_section.c)
- **Pros**: No VirtualAllocEx or WriteProcessMemory in target; memory is section-backed (harder to detect via VAD); shellcode write is local
- **Cons**: Still needs remote thread for execution; pagefile-backed sections are uncommon; NT API usage is a signal

### Module Stomping (inject_stomp.c)
- **Pros**: Shellcode runs from image-backed memory; passes VAD scans; thread start resolves to a known module
- **Cons**: Complex; uses CreateRemoteThread twice; disk/memory mismatch detectable by integrity checks; unusual DLL loads are behavioral signals

### Thread Hijacking (inject_threadhijack.c)
- **Pros**: No new thread created; bypasses thread creation callbacks entirely; hijacked thread resumes normally
- **Cons**: SuspendThread + SetThreadContext is monitored; risk of deadlock if thread is in a critical section; shellcode still in private memory

## Common Header

`include/injection.h` provides:
- NT API function pointer typedefs (NtCreateSection, NtMapViewOfSection, NtCreateThreadEx, etc.)
- NTSTATUS macros (NT_SUCCESS, STATUS_SUCCESS)
- Structure definitions (OBJECT_ATTRIBUTES, CLIENT_ID, PS_ATTRIBUTE_LIST)
- `ResolveNtFunction()` helper for runtime API resolution

## Building

Each file compiles standalone with `-DBUILD_STANDALONE`:

```
# MSVC
cl.exe /W4 /O2 /DBUILD_STANDALONE techniques\inject_crt.c /Fe:inject_crt.exe

# MinGW
x86_64-w64-mingw32-gcc -O2 -Wall -DBUILD_STANDALONE techniques/inject_crt.c -o inject_crt.exe

# Module stomping needs psapi
cl.exe /W4 /O2 /DBUILD_STANDALONE techniques\inject_stomp.c psapi.lib /Fe:inject_stomp.exe
```

Without `-DBUILD_STANDALONE`, each file exports:
```c
BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len);
```

## Adapting for Starburst PIC (Stardust Framework)

These reference implementations use standard Win32/NT APIs resolved via GetProcAddress. To integrate into Starburst's PIC codebase:

### 1. API Resolution
Replace all `GetModuleHandleA` / `GetProcAddress` calls with Stardust's API resolution:
```cpp
// Before (standard)
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
auto pNtCreateSection = (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");

// After (Stardust PIC)
auto pNtCreateSection = LdrFunction<fnNtCreateSection>(LdrModule("ntdll.dll"), "NtCreateSection");
```

### 2. Memory Operations
Replace standard C library calls with PIC-safe equivalents:
```cpp
// Before
memcpy(dst, src, len);
malloc(size);

// After (Stardust)
MemCopy(dst, src, len);
Instance()->Win32.HeapAlloc(Instance()->Win32.GetProcessHeap(), 0, size);
```

### 3. String Handling
Replace string literals with Stardust compile-time hashed strings or stack strings.

### 4. Error Handling
Replace fprintf/printf with Stardust's debug logging or remove entirely for release builds.

### 5. Integration Points
- **cmd_shinject.cc**: Direct shellcode injection into a specified PID. Any technique here can replace the current CRT-based implementation.
- **cmd_migrate.cc**: Process migration (spawn + inject + channel). Best candidates: Early Bird APC (spawns its own process) or Section Mapping + Thread Hijack combo.

### 6. Recommended Combinations
For maximum OPSEC, combine techniques:
- **Section Mapping + Thread Hijack**: Section-backed memory (no VirtualAllocEx) + no new thread (no thread creation callback). Highest stealth.
- **Module Stomping + Thread Hijack**: Image-backed memory (passes VAD scans) + no new thread. Best against memory scanners.
- **Early Bird APC + PPID Spoofing**: Clean process context + legitimate parent-child relationship. Good for migration.
