# Starburst Sleep Mask Kit

## Overview

The Sleep Mask Kit provides pre-built and customizable call stack spoofing profiles
for Starburst's Draugr sleep obfuscation system. During sleep, Draugr replaces the
agent's real call stack frames with synthetic frames that mimic legitimate Windows
thread patterns, making the sleeping thread appear benign to stack-walking detectors.

## How Draugr Call Stack Spoofing Works

When the agent enters its sleep cycle, Draugr performs the following sequence:

1. **Captures** the current thread context (registers, stack pointer).
2. **Encrypts** the agent's memory regions in-place.
3. **Overwrites** the thread's return addresses on the stack with the addresses
   defined in the active spoof profile, creating a synthetic call chain.
4. **Suspends** execution via a wait primitive (e.g., `NtWaitForSingleObject`).
5. On wake, **restores** the original stack frames and decrypts memory before
   resuming normal execution.

The synthetic frames are resolved at runtime by looking up function addresses in
loaded modules and adding the configured offset, producing return addresses that
point into the middle of real functions -- exactly as a legitimate call stack would.

## Spoof Profile Format

Each profile is a standalone header file that defines a `populate_spoof_frames()`
function. The file is designed to be copied directly to:

```
agent_code/include/evasion/spoof_profiles.h
```

### Key Structures

```c
#define SPOOF_MAX_FRAMES 10

struct SPOOF_FRAME_DEF {
    uint32_t module_hash;   // Compile-time hash of the module name (wide string)
    uint32_t func_hash;     // Compile-time hash of the function name, or 0 for RVA mode
    uint32_t offset;        // Byte offset into the function, or module RVA if func_hash == 0
};
```

### Frame Ordering

Frames are defined **innermost first, outermost last**. The first frame in the
array (index 0) is the deepest frame on the call stack (closest to the current
instruction pointer), and the last frame is the thread entry point (typically
`RtlUserThreadStart`).

This matches the order you would see when reading a debugger's call stack output
from top to bottom.

### Maximum Frames

A profile may contain at most **10 frames** (`SPOOF_MAX_FRAMES`). Most legitimate
Windows thread stacks have between 2 and 6 frames when idle, so profiles in that
range are realistic. Exceeding 10 frames will be silently truncated by the runtime.

## Address Resolution Modes

Each frame supports one of two resolution modes:

### Mode 1: Function + Offset (Portable)

Set `func_hash` to the compile-time hash of the exported function name and `offset`
to the byte offset into that function. At runtime, Draugr resolves the function's
address via the module's export table and adds the offset.

```c
frames[i].module_hash = expr::hash_string<wchar_t>(L"kernel32.dll");
frames[i].func_hash   = expr::hash_string("BaseThreadInitThunk");
frames[i].offset      = 0x14;
```

**Advantages:** Works across Windows versions as long as the function is exported.
The offset is relative to the function start, so it tolerates module base address
changes (ASLR).

**When to use:** For functions that are exported by name from system DLLs (most
ntdll.dll and kernel32.dll functions).

### Mode 2: Module RVA (Exact)

Set `func_hash` to `0` and `offset` to the Relative Virtual Address (RVA) within
the module. At runtime, Draugr adds the RVA directly to the module's base address.

```c
frames[i].module_hash = expr::hash_string<wchar_t>(L"combase.dll");
frames[i].func_hash   = 0;         // RVA mode
frames[i].offset      = 0x1234b;   // RVA of the target instruction
```

**Advantages:** Can target any address in a module, including non-exported or
C++-mangled functions, private helper routines, or mid-function points that are
not easily described by an export name.

**When to use:** For internal/private functions (e.g., `CRpcThread::WorkerLoop`
in combase.dll) that are not in the export table. Note that the RVA is
version-specific -- you may need to update it for different Windows builds.

## Creating Custom Profiles

### Step 1: Identify a Target Thread Pattern

Use a debugger or stack sampling tool to capture the idle call stack of a thread
type you want to mimic. For example, a standard thread's idle stack might look like:

```
ntdll!NtWaitForSingleObject+0x14
ntdll!RtlpWaitOnCriticalSection+0x37
kernel32!BaseThreadInitThunk+0x14
ntdll!RtlUserThreadStart+0x21
```

### Step 2: Determine Offsets with getFunctionOffset

For exported functions, use the `getFunctionOffset` utility to calculate the offset
of a specific return address within a function:

```
getFunctionOffset ntdll.dll RtlUserThreadStart 0x21
```

This confirms that the return address at offset `0x21` inside `RtlUserThreadStart`
is a valid `call` return site.

For non-exported functions, disassemble the module to find the target RVA and use
Module RVA mode instead.

### Step 3: Build the Profile

Create a new header file following the template. Define frames innermost-first,
and set `*count` to the number of frames. Each frame needs:

- `module_hash`: `expr::hash_string<wchar_t>(L"modulename.dll")`
- `func_hash`: `expr::hash_string("FunctionName")` or `0` for RVA mode
- `offset`: byte offset into the function, or module RVA

### Step 4: Deploy

Copy your completed header to `agent_code/include/evasion/spoof_profiles.h` and
rebuild the agent. The new profile will be active on the next sleep cycle.

## Using Pre-Built Profiles

The `profiles/` directory contains ready-to-use profiles for common Windows thread
patterns:

| File                    | Pattern                          | Frames | Notes                                    |
|-------------------------|----------------------------------|--------|------------------------------------------|
| `thread_2frame.h`       | Standard thread entry            | 2      | Most common idle thread pattern          |
| `worker_2frame.h`       | Thread pool worker               | 2      | Seen in services and background workers  |
| `threadpool_3frame.h`   | Thread pool with TpReleasePool   | 3      | Common in .NET and COM applications      |
| `combase_4frame.h`      | COM RPC worker thread            | 4      | Uses RVA mode for combase.dll internal   |
| `wmi_3frame.h`          | WMI provider host worker         | 3      | Mimics WmiPrvSE.exe worker threads       |

To use a pre-built profile, copy it into your agent build tree:

```
copy profiles\thread_2frame.h agent_code\include\evasion\spoof_profiles.h
```

Then rebuild the agent.

## Choosing a Profile

Select a profile that matches the expected execution context of your agent:

- **Injected into svchost.exe or a service:** `worker_2frame.h` or `threadpool_3frame.h`
- **Running as a standalone executable:** `thread_2frame.h`
- **Injected into a COM-heavy process (e.g., explorer.exe, MMC):** `combase_4frame.h`
- **Injected into WmiPrvSE.exe:** `wmi_3frame.h`
- **Custom process:** Create a profile matching that process's idle thread stacks

## Operational Notes

- Offsets are based on Windows 10/11 x64 builds. Verify offsets against your target
  OS version, especially for RVA-mode frames.
- The spoofed stack is only present during the sleep window. Once the agent wakes,
  the original stack is restored.
- Stack spoofing complements but does not replace other sleep obfuscation features
  (memory encryption, timer-based wake, etc.).
