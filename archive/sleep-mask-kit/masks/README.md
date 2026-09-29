# Sleep Mask Implementations

Alternative masking implementations for Starburst's sleep-time evasion. Each file provides drop-in replacement logic for `evasion.cc`'s `evasion_pre_sleep()` / `evasion_post_sleep()` functions.

## Current Default

Starburst's built-in masking (`evasion.cc`) XOR-masks three fields during sleep:
- AES-256 session key (32 bytes)
- Callback UUID (36 bytes)
- Payload UUID (36 bytes)

This is lightweight but only covers ~104 bytes of sensitive data. The agent's code, heap, and instance struct remain in plaintext.

## Available Masks

| Mask | What It Covers | OPSEC Level | Performance |
|------|---------------|-------------|-------------|
| `mask_full_image.h` | Entire shellcode image (`.text` + data) | HIGH | Medium (RW↔RX flip required) |
| `mask_heap.h` | Sensitive data + all heap allocations | MEDIUM-HIGH | Low overhead |
| `mask_ekko.h` | Full image via timer queue ROP chain | VERY HIGH | Medium (CreateTimerQueueTimer) |

## How to Use

1. Pick a mask implementation
2. Copy the relevant code into `agent_code/src/evasion/evasion.cc`, replacing `evasion_pre_sleep()` and `evasion_post_sleep()`
3. Add any new struct fields to the `ekko` struct in `common.h` if needed
4. Rebuild the agent

## Considerations

- **Full image masking** requires flipping `.text` to RW before XOR and back to RX after. This generates `VirtualProtect` calls that some EDRs monitor.
- **Ekko-style masking** uses `CreateTimerQueueTimer` + `NtContinue` ROP to mask from a different thread context, avoiding direct `VirtualProtect` calls from the agent thread.
- **Heap masking** walks the process heap and masks allocations, catching any dynamically allocated sensitive data (parsed task responses, etc.).
