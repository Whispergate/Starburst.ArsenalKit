# Starburst Arsenal Kit

Operator customization kit for the [Starburst](https://github.com/Whispergate/Starburst) Mythic agent. Provides delivery templates, injection techniques, sleep evasion profiles, artifact wrappers, and operator utilities — adapted from Cobalt Strike's Arsenal Kit pattern for Mythic.

## Kit Overview

| Kit | Purpose | Key Files |
|-----|---------|-----------|
| **sleep-mask-kit** | Call stack spoof profiles + sleep masking customization | `profiles/*.h` |
| **artifact-kit** | EXE/DLL/SVC wrappers with evasion bypass techniques | `src/*.c`, `bypass/*.c` |
| **loader-kit** | Module stomping and DLL sideloading loaders | `stomper/`, `sideload/` |
| **injection-kit** | Alternative process injection techniques for shinject/migrate | `techniques/*.c` |
| **resource-kit** | Delivery stagers (PowerShell, HTA, VBS, Python, C#, MSBuild) | Per-language subdirectories |
| **utils** | Operator tools (hash generator, offset calculator, encoder) | Per-tool subdirectories |

## Quick Start

### 1. Sleep Mask Kit — Custom Call Stack Spoof Profile

```bash
# Calculate offsets on your target Windows version
utils/getFunctionOffset/getFunctionOffset.exe ntdll.dll TpReleasePool 0x402
utils/getFunctionOffset/getFunctionOffset.exe kernel32.dll BaseThreadInitThunk 0x14
utils/getFunctionOffset/getFunctionOffset.exe ntdll.dll RtlUserThreadStart 0x21

# Copy a pre-built profile into agent source
cp sleep-mask-kit/profiles/threadpool_3frame.h \
   <starburst>/agent_code/include/evasion/spoof_profiles.h

# Build with: spoof_profile = custom
```

### 2. Resource Kit — Deploy Starburst Shellcode

```powershell
# Generate Starburst .bin via Mythic (output_type = bin), then:

# PowerShell — VirtualAlloc + CreateThread
powershell -ep bypass -f resource-kit/powershell/stager_valloc.ps1

# C# — NtCreateSection + NtMapViewOfSection
csc /unsafe /out:loader.exe resource-kit/csharp/SectionLoader.cs

# Python — ctypes VirtualAlloc
python resource-kit/python/stager_ctypes.py payload.bin
```

### 3. Injection Kit — Swap Injection Technique

Replace default `CreateRemoteThread` in `cmd_shinject.cc` or `cmd_migrate.cc` with alternative technique from `injection-kit/techniques/`.

### 4. Artifact Kit — Custom Wrappers

```bash
# Compile EXE wrapper with pipe bypass
x86_64-w64-mingw32-gcc -O2 -s artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c -o starburst.exe -lkernel32

# Compile DLL wrapper
x86_64-w64-mingw32-gcc -O2 -s -shared artifact-kit/src/main_dll.c \
    artifact-kit/bypass/bypass_fiber.c -o starburst.dll -lkernel32
```

## Build Requirements

- **C/C++ compilation**: MinGW-w64 (`x86_64-w64-mingw32-gcc`) or MSVC (`cl.exe`)
- **C# compilation**: .NET SDK 6.0+ or `csc.exe`
- **Python**: 3.8+ (for encoder utilities and Python stagers)
- **PowerShell**: 5.1+ (target systems)

## Relationship to Starburst Agent

This kit is **external** to the Starburst agent source tree. It provides:

1. **Pre-deployment tools** — stagers and wrappers that deliver Starburst shellcode to target
2. **Agent source patches** — drop-in `.h` files for `spoof_profiles.h`, injection technique replacements
3. **Operator utilities** — offset calculators, hash generators, payload encoders

The agent itself is built via Mythic's payload builder (or manually via Makefile). This kit supplements that workflow.
