# UDRL Sleep Mask Kit - Top-level build
#
# Builds both the reflective loader and the sleep mask as
# relocatable object files for Crystal Palace linking.
#
# Usage:
#   make                    # Build everything (Ekko mask, VirtualAlloc loader)
#   make MASK_TYPE=1        # Build with full-image XOR mask
#   make LOAD_MODE=1        # Build loader in module stomping mode
#   make clean              # Remove build artifacts
#
# Mask types:
#   0 = Ekko (timer queue ROP + RC4, x64 only)
#   1 = Full Image XOR (x86/x64)
#   2 = Heap only (x86/x64)
#
# Load modes:
#   0 = VirtualAlloc (standard)
#   1 = Module Stomp (stomps sacrificial DLL)

MASK_TYPE   ?= 0
ENABLE_CFG  ?= 1
ENABLE_HEAP ?= 1
LOAD_MODE   ?= 0

export MASK_TYPE ENABLE_CFG ENABLE_HEAP LOAD_MODE

.PHONY: all clean loader mask

all: loader mask

loader:
	$(MAKE) -C loader

mask:
	$(MAKE) -C mask

clean:
	$(MAKE) -C loader clean
	$(MAKE) -C mask clean
