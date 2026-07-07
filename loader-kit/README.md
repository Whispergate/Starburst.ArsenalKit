# Starburst Arsenal Kit - Loader Kit

## Overview

The loader kit provides two complementary techniques for executing Starburst shellcode
from disk while evading common detection mechanisms. Each technique has different
trade-offs in terms of OPSEC, complexity, and operational flexibility.

---

## Techniques

### 1. Module Stomping (`stomper/`)

**What it does:** Loads a legitimate, signed Windows DLL into the process, then
overwrites its `.text` (executable code) section with your shellcode. The shellcode
executes from memory that is backed by a legitimate image file on disk.

**Why it matters:**

- Thread start addresses point to a Microsoft-signed module, not unbacked memory
- VAD (Virtual Address Descriptor) entries show `MEM_IMAGE` type, not `MEM_PRIVATE`
- Memory scanners that skip image-backed regions will miss the payload entirely
- ETW thread-creation events show a legitimate module as the start address

**When to use:**

- Post-exploitation, when you already have code execution and need to run shellcode
  with reduced forensic footprint
- When EDR is performing VAD-based scanning or thread-start-address heuristics
- When you need a standalone loader (no DLL planting required)

**Files:**

- `stomper.c` -- Complete module stomping loader
- `sacrificial_dlls.h` -- Curated list of DLLs suitable for stomping

---

### 2. DLL Sideloading (`sideload/`)

**What it does:** Creates a proxy DLL that masquerades as a DLL that a legitimate,
signed application expects to load. When the application starts, it loads your proxy
DLL, which forwards all real exports to the original DLL (loaded from its real path)
while executing shellcode on `DLL_PROCESS_ATTACH`.

**Why it matters:**

- Execution is triggered by a legitimate, signed binary (LOLBin-style)
- The proxy DLL is loaded via the normal Windows loader, appearing as a standard
  library dependency
- Parent process is a trusted application, which can bypass parent-process heuristics
- Can achieve persistence by placing the proxy DLL alongside an auto-start application

**When to use:**

- Initial access or persistence, when you can write files to disk
- When you need execution to appear as a child of a trusted, signed process
- When you want to bypass application whitelisting that trusts the host binary
- When EDR is monitoring for suspicious process trees

**Files:**

- `sideload_template.c` -- Proxy DLL template (version.dll example)
- `targets.md` -- Known sideload-vulnerable signed binaries

---

## OPSEC Comparison

| Factor                     | Module Stomping              | DLL Sideloading              |
|----------------------------|------------------------------|------------------------------|
| **Disk artifacts**         | None (in-memory only)        | Proxy DLL on disk            |
| **Memory forensics**       | Strong -- image-backed       | Moderate -- normal DLL load  |
| **Thread start address**   | Points to signed module      | Points to proxy DLL          |
| **VAD type**               | MEM_IMAGE (legitimate)       | MEM_IMAGE (legitimate)       |
| **Parent process**         | Current process              | Trusted signed application   |
| **Persistence potential**  | No (runtime only)            | Yes (with auto-start binary) |
| **Complexity**             | Low                          | Medium (export forwarding)   |
| **Detection surface**      | .text section mismatch       | Unsigned DLL next to signed exe |
| **Pre-requisites**         | Code execution               | File write access            |
| **Best against**           | VAD scanning, thread checks  | Process tree heuristics      |

### Combined Usage

For maximum OPSEC, combine both techniques:

1. Use DLL sideloading to get initial execution from a trusted process
2. The sideloaded DLL's shellcode performs module stomping to run the final payload
3. Result: trusted parent process + image-backed memory for payload execution

---

## Build Requirements

- MinGW-w64 cross-compiler (`x86_64-w64-mingw32-gcc`)
- Target: Windows x86_64
- No external dependencies beyond Windows API

## Quick Build

```bash
# Module stomping loader
x86_64-w64-mingw32-gcc -O2 -s stomper/stomper.c -o stomper.exe -lkernel32

# Sideload proxy DLL
x86_64-w64-mingw32-gcc -shared -O2 -s sideload/sideload_template.c \
    -o version.dll -lkernel32
```
