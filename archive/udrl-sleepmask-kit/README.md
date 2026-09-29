# UDRL Sleep Mask Kit

User-Defined Reflective Loader and Sleep Mask for the Starburst agent. Replaces the default Crystal Palace loader with a reflective DLL loader and adds encrypted sleep obfuscation with API proxying.

## Overview

The kit has two main components:

- **Loader** - PIC reflective DLL loader that parses PE headers, maps sections, resolves imports, processes relocations, and calls DllMain. Supports standard `VirtualAlloc` and module stomping modes.
- **Mask** - PIC sleep obfuscation that encrypts the agent's memory during sleep. Supports Ekko (timer queue ROP + RC4), full image XOR, and heap masking. Includes BeaconGate-style API proxying.

Both components compile to relocatable `.o` files for Crystal Palace linking.

## Directory Structure

```
udrl-sleepmask-kit/
├── Makefile                          # Top-level build
├── README.md
├── common/include/
│   ├── pic_defs.h                    # PIC definitions, hashing, PEB resolution, API typedefs
│   ├── user_data.h                   # UDRL_USER_DATA bridge struct (loader → agent → mask)
│   └── cfg_bypass.h                  # CFG bitmap bypass for Ekko timer callbacks
├── loader/
│   ├── Makefile
│   ├── loader.spec                   # Crystal Palace linker specification
│   ├── bin/                          # Build output
│   │   └── loader.x64.o
│   └── src/
│       └── loader.c                  # Reflective DLL loader
└── mask/
    ├── Makefile
    ├── mask.spec                     # Crystal Palace linker specification
    ├── bin/                          # Build output
    │   └── mask.x64.o
    ├── profiles/
    │   └── thread_2frame.h           # 2-frame call stack spoof profile
    └── src/
        └── mask.c                    # Sleep mask + BeaconGate proxies
```

## Prerequisites

- `x86_64-w64-mingw32-gcc` (MinGW-w64 cross-compiler)
- `make`
- Crystal Palace (`crystalpalace.jar`) for final PIC linking
- Java runtime (for Crystal Palace)

## Building

### Default Build (Ekko mask, VirtualAlloc loader)

```bash
make
```

### Build Options

| Variable      | Values                                    | Default |
|---------------|-------------------------------------------|---------|
| `MASK_TYPE`   | `0` (Ekko), `1` (Full Image), `2` (Heap) | `0`     |
| `LOAD_MODE`   | `0` (VirtualAlloc), `1` (Module Stomp)    | `0`     |
| `ENABLE_CFG`  | `0` (disabled), `1` (enabled)             | `1`     |
| `ENABLE_HEAP` | `0` (disabled), `1` (enabled)             | `1`     |
| `STOMP_DLL`   | Sacrificial DLL name (module stomp only)  | `dbghelp.dll` |

#### Examples

```bash
# Ekko mask with module stomping
make LOAD_MODE=1

# Ekko mask with custom stomp target
make LOAD_MODE=1 STOMP_DLL="xpsservices.dll"

# Full image XOR (x86/x64 compatible, no timer queue)
make MASK_TYPE=1

# Heap-only masking (minimal, no image encryption)
make MASK_TYPE=2

# Ekko without CFG bypass (older Windows, no CFG)
make ENABLE_CFG=0

# Ekko without heap masking
make ENABLE_HEAP=0

# Full image XOR + module stomping, no heap
make MASK_TYPE=1 LOAD_MODE=1 ENABLE_HEAP=0
```

### Build Individual Components

```bash
make loader    # Only build the reflective loader
make mask      # Only build the sleep mask
make clean     # Remove build artifacts
```

## Integration with Crystal Palace

### Replacing the Default Loader

1. Build the loader object:
   ```bash
   cd loader && make
   ```

2. Copy `loader.spec` and `bin/loader.x64.o` to your Crystal Palace loader directory, replacing the default loader files.

3. The spec file tells Crystal Palace to:
   - Load the compiled object
   - Make it PIC with `go()` as entry point
   - Patch `KERNEL32$` / `NTDLL$` references via ROR13 DFR
   - Append the Starburst DLL payload into the `shellcode` section
   - Prepend a 4-byte length prefix (`preplen`)

4. Crystal Palace links as normal:
   ```bash
   java -jar crystalpalace.jar build/link
   ```

### Using the Sleep Mask

The mask is a standalone PIC module. The agent calls `mask_sleep()` instead of `NtDelayExecution`:

```c
// In the agent's sleep loop:
extern void mask_sleep(UDRL_USER_DATA *ud, DWORD time_ms);

// ud was received via lpvReserved in DllMain
mask_sleep(user_data, sleep_duration_ms);
```

### BeaconGate API Proxies

The mask exports proxy functions that obfuscate the agent during sensitive API calls:

```c
// Instead of calling VirtualAlloc directly:
LPVOID mem = gate_VirtualAlloc(ud, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

// Instead of VirtualProtect:
gate_VirtualProtect(ud, addr, size, PAGE_EXECUTE_READ, &old);

// Instead of CreateThread:
HANDLE t = gate_CreateThread(ud, NULL, 0, start, param, 0, NULL);
```

Each proxy:
1. Flips the agent image to RW
2. XOR-encrypts the agent image
3. Calls the real WinAPI
4. XOR-decrypts the agent image
5. Restores original memory protection

The agent is encrypted during the API call, so memory scanners triggered by the API see only noise.

## Loader Modes

### VirtualAlloc (LOAD_MODE=0)

Standard reflective loading. Allocates private memory with `VirtualAlloc`, maps PE sections, resolves imports. The resulting memory region is `MEM_PRIVATE`.

**Pros:** Simple, reliable, works everywhere.
**Cons:** Private RWX→RX memory is suspicious. Tools like Moneta flag unbacked executable private regions.

### Module Stomping (LOAD_MODE=1)

Loads a sacrificial DLL with `LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES)`, finds its `.text` section, and overwrites it with the agent. The resulting memory appears as `MEM_IMAGE` backed by a legitimate DLL.

**Pros:** Memory appears as a loaded DLL module. Bypasses Moneta-style unbacked memory detection.
**Cons:** The stomped DLL must have a `.text` section large enough for the agent. Some EDRs detect mismatches between the on-disk DLL and in-memory contents.

**Choosing a stomp target:** Pick a DLL that:
- Has a `.text` section larger than the agent image
- Is not commonly loaded (avoids double-load detection)
- Ships with Windows (present on all targets)

Good candidates: `dbghelp.dll`, `xpsservices.dll`, `msdart.dll`

## Mask Types

### Ekko (MASK_TYPE=0, x64 only)

Timer queue ROP chain using `NtContinue` and `SystemFunction032` (RC4). The entire masking/unmasking sequence runs from a system timer thread, not the agent thread.

**Flow:**
1. Create timer queue and sync event
2. Capture clean CONTEXT via `RtlCaptureContext` timer callback
3. Build ROP contexts for each step
4. Queue timers: `VirtualProtect(RW)` → `RC4 encrypt` → sleep → `RC4 decrypt` → `VirtualProtect(RX)` → `SetEvent`
5. Agent thread blocks on `WaitForSingleObject`
6. Timer thread executes the ROP chain

**Strengths:**
- RC4 encryption (not simple XOR)
- Protection changes come from system thread, not agent
- Agent thread has clean call stack during sleep
- Combined with heap masking for comprehensive coverage

**CFG bypass:** When `ENABLE_CFG=1`, registers `NtContinue` and `RtlCaptureContext` as valid call targets via `SetProcessValidCallTargets` before creating timers. Required for CFG-enabled processes (most modern Windows).

### Full Image XOR (MASK_TYPE=1)

XOR encryption of the agent image with a 16-byte key. Runs from the agent thread with a skip region to avoid encrypting its own executing code.

**Flow:**
1. `VirtualProtect` → RW
2. XOR image (skip the mask function's own code)
3. `NtDelayExecution` (sleep)
4. XOR image (restore)
5. `VirtualProtect` → RX

**Strengths:**
- Works on x86 and x64
- No timer queue (simpler, fewer behavioral signatures)
- Still encrypts the vast majority of the agent image

**Weakness:** The masking code itself remains unencrypted (~512 bytes). For complete coverage, use Ekko.

### Heap Only (MASK_TYPE=2)

XOR masking of process heap blocks via `HeapWalk`. No image encryption. Minimal evasion, primarily for environments where memory protection changes are heavily monitored.

## User Data Structure

The `UDRL_USER_DATA` struct bridges the loader, agent, and mask:

```c
typedef struct _UDRL_USER_DATA {
    UINT64    magic;              // 0x5442525354 ("STRBT") - validity check
    DWORD     load_type;          // LOAD_TYPE_VIRTUAL_ALLOC or LOAD_TYPE_MODULE_STOMP

    PVOID     agent_base;         // Base of mapped agent image
    DWORD     agent_size;         // Total image size

    PVOID     loader_base;        // Initial allocation (for cleanup)
    DWORD     loader_size;

    HMODULE   stomped_module;     // Sacrificial DLL handle (module stomp only)
    PVOID     stomped_text_base;  // Stomped .text base
    DWORD     stomped_text_size;  // Stomped .text size

    UDRL_REGION regions[8];       // Memory regions to mask during sleep
    DWORD     region_count;

    BYTE      rc4_key[16];        // Encryption key (generated from RDTSC)
    BYTE      reserved[64];       // Future use
} UDRL_USER_DATA;
```

The loader populates this struct and passes it to the agent as `lpvReserved` in `DllMain`. The agent stores the pointer and passes it to `mask_sleep()` and the BeaconGate proxy functions.

## Call Stack Spoof Profiles

The `mask/profiles/` directory contains call stack spoof definitions. The included `thread_2frame.h` provides a standard 2-frame thread start stack:

```
kernel32!BaseThreadInitThunk+0x14
ntdll!RtlUserThreadStart+0x21
```

To add custom profiles, create a new header in `profiles/` defining `SPOOF_FRAME_DEF` entries with `module_hash`, `func_hash`, and `offset` fields.

## Common Headers

### pic_defs.h

Core PIC infrastructure:
- **FNV-1a hashing** - `fnv1a_hash_a()` / `fnv1a_hash_w()` matching the Starburst agent's hash algorithm
- **PEB resolution** - `resolve_module()` walks the PEB InMemoryOrderModuleList using raw offsets (no struct dependency)
- **API resolution** - `resolve_api()` walks PE export directory, `resolve_api_forwarded()` follows one level of export forwarding
- **Memory helpers** - `pic_memcpy()`, `pic_memset()`, `pic_memcmp()`
- **API typedefs** - NT and Win32 function pointer types

### user_data.h

Bridge struct definitions. See [User Data Structure](#user-data-structure).

### cfg_bypass.h

CFG bitmap manipulation:
- `cfg_add_valid_target()` - Register a single address as valid CFG call target
- `cfg_register_ekko_targets()` - Register NtContinue + RtlCaptureContext for Ekko

## Troubleshooting

**Build fails with "Cannot create temporary file"**
Your system temp directory isn't writable. The Makefiles use `-pipe` to avoid temp files. If you still see this, set `TMPDIR` to a writable location.

**Module stomp fails at runtime**
The sacrificial DLL's `.text` section is smaller than the agent image. Use `dumpbin /headers <dll>` to check the .text virtual size, or pick a larger DLL.

**Ekko crashes on older Windows**
CFG bypass may not work on Windows versions before 10. Set `ENABLE_CFG=0` or use `MASK_TYPE=1` (Full Image XOR).

**Agent crashes after sleep**
Verify the `UDRL_USER_DATA` magic field matches. Check that `agent_base` and `agent_size` accurately describe the mapped image. If module stomping, ensure the stomped region isn't being used by another loaded module.
