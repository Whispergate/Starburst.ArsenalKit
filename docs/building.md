# Build Instructions

Compiler setup, flags, and build examples for every Arsenal Kit component.

---

## Compiler Setup

### MinGW-w64 (Linux Cross-Compilation)

The recommended approach for building Arsenal Kit components from a Linux attack box.

```bash
# Debian/Ubuntu
sudo apt-get install mingw-w64 mingw-w64-tools

# Verify installation
x86_64-w64-mingw32-gcc --version
i686-w64-mingw32-gcc --version    # 32-bit (if needed)
```

This gives you:
- `x86_64-w64-mingw32-gcc` -- 64-bit C compiler
- `x86_64-w64-mingw32-g++` -- 64-bit C++ compiler
- `x86_64-w64-mingw32-windres` -- resource compiler (for `.rc` files)
- `x86_64-w64-mingw32-strip` -- strip symbols from binaries

### MinGW-w64 (Windows via MSYS2)

For building on Windows without Visual Studio:

```powershell
# Install MSYS2 from https://www.msys2.org/
# Then in MSYS2 terminal:
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-make

# Add to PATH (PowerShell)
$env:PATH += ";C:\msys64\mingw64\bin"
```

### MSVC (Visual Studio Developer Command Prompt)

Required for components that use MSVC-specific features or when you need matching PDB/Rich header signatures.

```powershell
# Option 1: Open "x64 Native Tools Command Prompt for VS 2022" from Start Menu

# Option 2: Initialize from PowerShell
& "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

# Verify
cl.exe /? 2>&1 | Select-Object -First 1
```

Key MSVC tools:
- `cl.exe` -- C/C++ compiler
- `link.exe` -- linker
- `rc.exe` -- resource compiler
- `lib.exe` -- static library manager
- `dumpbin.exe` -- PE inspection tool

---

## Compiler Flags Reference

### Size Optimization (Recommended for Payloads)

```bash
# MinGW -- minimize output size
CFLAGS="-Os -s -fno-ident -fno-exceptions -fno-asynchronous-unwind-tables \
        -ffunction-sections -fdata-sections -Wl,--gc-sections"

# MSVC -- minimize output size
CFLAGS="/O1 /Os /GS- /GL /Gy"
LDFLAGS="/OPT:REF /OPT:ICF /LTCG"
```

### Security Flags (Match Legitimate Binaries)

```bash
# MinGW -- enable ASLR, DEP, CFG
LDFLAGS="-Wl,--dynamicbase,--nxcompat,--high-entropy-va"

# MSVC
LDFLAGS="/DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA"
```

### Debug Flags (Development Only)

```bash
# MinGW
CFLAGS="-g -O0 -DDEBUG"

# MSVC
CFLAGS="/Zi /Od /DDEBUG"
```

### Flag Summary Table

| Flag (MinGW) | Flag (MSVC) | Purpose |
|--------------|-------------|---------|
| `-Os` | `/O1 /Os` | Optimize for size |
| `-O2` | `/O2` | Optimize for speed |
| `-s` | (use `/link /OPT:REF`) | Strip symbols |
| `-fno-ident` | N/A | Remove compiler identification strings |
| `-mwindows` | `/link /SUBSYSTEM:WINDOWS` | GUI application (no console) |
| `-mconsole` | `/link /SUBSYSTEM:CONSOLE` | Console application |
| `-shared` | `/LD` | Build shared library (DLL) |
| `-nostdlib` | `/NODEFAULTLIB` | No CRT linkage |
| `-Wl,--dynamicbase` | `/DYNAMICBASE` | Enable ASLR |
| `-Wl,--nxcompat` | `/NXCOMPAT` | Enable DEP |

---

## Build Examples by Kit Component

### Utils: getFunctionOffset

```bash
# MinGW (cross-compile from Linux)
x86_64-w64-mingw32-gcc -O2 \
    utils/getFunctionOffset/getFunctionOffset.c \
    -o getFunctionOffset.exe

# MSVC (from Developer Command Prompt)
cl.exe /nologo /O2 \
    utils\getFunctionOffset\getFunctionOffset.c \
    /Fe:getFunctionOffset.exe
```

### Artifact Kit: EXE Wrapper

```bash
# MinGW -- EXE with pipe bypass, size-optimized
x86_64-w64-mingw32-gcc -Os -s \
    -fno-ident -fno-exceptions \
    artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c \
    -o starburst.exe \
    -lkernel32 \
    -mwindows \
    -Wl,--dynamicbase,--nxcompat

# MinGW -- EXE with custom resources (icon + metadata)
x86_64-w64-mingw32-windres artifact-kit/src/resource.rc -o resource.o
x86_64-w64-mingw32-gcc -Os -s \
    artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c \
    resource.o \
    -o starburst.exe \
    -lkernel32 -mwindows

# MSVC -- EXE with fiber bypass
cl.exe /nologo /O1 /Os /GS- \
    artifact-kit\src\main_exe.c \
    artifact-kit\bypass\bypass_fiber.c \
    /Fe:starburst.exe \
    /link kernel32.lib /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT
```

### Artifact Kit: DLL Wrapper

```bash
# MinGW -- DLL with callback bypass
x86_64-w64-mingw32-gcc -Os -s -shared \
    artifact-kit/src/main_dll.c \
    artifact-kit/bypass/bypass_callback.c \
    -o starburst.dll \
    -lkernel32 \
    -Wl,--dynamicbase,--nxcompat

# MSVC -- DLL
cl.exe /nologo /O1 /Os /GS- /LD \
    artifact-kit\src\main_dll.c \
    artifact-kit\bypass\bypass_callback.c \
    /Fe:starburst.dll \
    /link kernel32.lib /DYNAMICBASE /NXCOMPAT
```

### Artifact Kit: Service EXE

```bash
# MinGW -- Service binary (console subsystem for SCM interaction)
x86_64-w64-mingw32-gcc -Os -s \
    artifact-kit/src/main_svc.c \
    artifact-kit/bypass/bypass_pipe.c \
    -o starburst_svc.exe \
    -lkernel32 -ladvapi32 \
    -mconsole \
    -Wl,--dynamicbase,--nxcompat
```

### Loader Kit: Module Stomper

```bash
# MinGW -- stomper DLL
x86_64-w64-mingw32-gcc -Os -s -shared \
    loader-kit/stomper/stomper.c \
    -o stomper.dll \
    -lkernel32 -lntdll \
    -Wl,--dynamicbase,--nxcompat

# MSVC -- stomper DLL
cl.exe /nologo /O1 /Os /GS- /LD \
    loader-kit\stomper\stomper.c \
    /Fe:stomper.dll \
    /link kernel32.lib ntdll.lib /DYNAMICBASE /NXCOMPAT
```

### Loader Kit: Sideloading Proxy DLL

```bash
# Step 1: Generate proxy .def from target DLL exports
python loader-kit/sideload/gen_proxy_def.py exports.txt version.dll > version.def

# Step 2: Compile with proxy forwards
x86_64-w64-mingw32-gcc -Os -s -shared \
    loader-kit/sideload/sideload_main.c \
    -o version.dll \
    -Wl,--def=version.def \
    -lkernel32 \
    -Wl,--dynamicbase,--nxcompat
```

### Resource Kit: C# Stager

```bash
# .NET SDK (cross-platform)
dotnet build resource-kit/csharp/SectionLoader.csproj -c Release

# csc.exe directly (Windows)
csc.exe /unsafe /optimize /out:loader.exe \
    resource-kit/csharp/SectionLoader.cs

# Mono (Linux)
mcs -unsafe -optimize -out:loader.exe \
    resource-kit/csharp/SectionLoader.cs
```

### Resource Kit: PowerShell Stager

PowerShell stagers do not need compilation. To obfuscate:

```powershell
# Basic variable renaming and string encoding
python resource-kit/powershell/obfuscate.py stager_valloc.ps1 > stager_out.ps1
```

---

## Cross-Compilation from Linux

All C/C++ kit components support cross-compilation from Linux using MinGW-w64.

### Full Cross-Compile Workflow

```bash
# Install cross-compiler
sudo apt-get install mingw-w64

# Clone the Arsenal Kit
git clone <repo> && cd Starburst.ArsenalKit

# Build getFunctionOffset
x86_64-w64-mingw32-gcc -O2 \
    utils/getFunctionOffset/getFunctionOffset.c \
    -o build/getFunctionOffset.exe

# Build artifact EXE (pipe bypass, with resources)
x86_64-w64-mingw32-windres artifact-kit/src/resource.rc -o build/resource.o
x86_64-w64-mingw32-gcc -Os -s \
    artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c \
    build/resource.o \
    -o build/starburst.exe \
    -lkernel32 -mwindows

# Build artifact DLL (fiber bypass)
x86_64-w64-mingw32-gcc -Os -s -shared \
    artifact-kit/src/main_dll.c \
    artifact-kit/bypass/bypass_fiber.c \
    -o build/starburst.dll \
    -lkernel32

# Build sideloading DLL
x86_64-w64-mingw32-gcc -Os -s -shared \
    loader-kit/sideload/sideload_main.c \
    -o build/version.dll \
    -Wl,--def=version.def \
    -lkernel32
```

### 32-bit Builds

Replace `x86_64-w64-mingw32-gcc` with `i686-w64-mingw32-gcc` for 32-bit output. This is rarely needed -- most targets are 64-bit.

```bash
i686-w64-mingw32-gcc -Os -s \
    artifact-kit/src/main_exe.c \
    artifact-kit/bypass/bypass_pipe.c \
    -o starburst_x86.exe \
    -lkernel32 -mwindows
```

---

## Size Optimization Checklist

For minimum payload size, apply all of these:

```bash
x86_64-w64-mingw32-gcc \
    -Os                              # Optimize for size \
    -s                               # Strip all symbols \
    -fno-ident                       # Remove GCC version string \
    -fno-exceptions                  # No C++ exception handling \
    -fno-asynchronous-unwind-tables  # No .eh_frame section \
    -ffunction-sections              # Each function in own section \
    -fdata-sections                  # Each data item in own section \
    -Wl,--gc-sections                # Remove unused sections \
    -nostdlib                        # No CRT (requires custom entry) \
    -lkernel32                       # Link only what you need \
    source.c -o output.exe
```

Post-build stripping:

```bash
# Additional stripping after build
x86_64-w64-mingw32-strip --strip-all output.exe

# Verify final size
ls -la output.exe
file output.exe
```

Typical sizes with full optimization:

| Component | Unoptimized | Optimized |
|-----------|-------------|-----------|
| Artifact EXE (pipe bypass) | ~45 KB | ~8-12 KB |
| Artifact DLL (fiber bypass) | ~40 KB | ~6-10 KB |
| Sideloading proxy DLL | ~35 KB | ~5-8 KB |
| getFunctionOffset.exe | ~25 KB | ~10 KB |
