# Starburst ArsenalKit — BOF Cross-Compilation Makefile
#
# Usage:
#   make              — build all BOFs (x64)
#   make ARCH=x86     — build all BOFs (x86)
#   make clean        — remove all build artifacts
#   make process-kit  — build only process-kit BOFs
#
# Requirements: mingw-w64 cross-compiler (x86_64-w64-mingw32-gcc)

ARCH     ?= x64
OUTDIR   := bin/$(ARCH)
INCLDIR  := include

ifeq ($(ARCH),x64)
    CC := x86_64-w64-mingw32-gcc
else
    CC := i686-w64-mingw32-gcc
endif

CFLAGS := -c -pipe -DBOF -I$(INCLDIR) -Wall -Wno-unused-variable -Os

# ── Source discovery ──
PROCESS_SRC     := $(wildcard src/process-kit/*.c)
AMSI_ETW_SRC    := $(wildcard src/amsi-etw-kit/*.c)
PERSIST_SRC     := $(wildcard src/persistence-kit/*.c)
CRED_SRC        := $(wildcard src/credential-kit/*.c)
UTIL_SRC        := $(wildcard src/utility-kit/*.c)

ALL_SRC := $(PROCESS_SRC) $(AMSI_ETW_SRC) $(PERSIST_SRC) $(CRED_SRC) $(UTIL_SRC)

# BOF output: src/foo-kit/bar.c → bin/x64/bar.o
PROCESS_OBJ     := $(patsubst src/process-kit/%.c,$(OUTDIR)/%.o,$(PROCESS_SRC))
AMSI_ETW_OBJ    := $(patsubst src/amsi-etw-kit/%.c,$(OUTDIR)/%.o,$(AMSI_ETW_SRC))
PERSIST_OBJ     := $(patsubst src/persistence-kit/%.c,$(OUTDIR)/%.o,$(PERSIST_SRC))
CRED_OBJ        := $(patsubst src/credential-kit/%.c,$(OUTDIR)/%.o,$(CRED_SRC))
UTIL_OBJ        := $(patsubst src/utility-kit/%.c,$(OUTDIR)/%.o,$(UTIL_SRC))

ALL_OBJ := $(PROCESS_OBJ) $(AMSI_ETW_OBJ) $(PERSIST_OBJ) $(CRED_OBJ) $(UTIL_OBJ)

# ── Targets ──

.PHONY: all clean process-kit amsi-etw-kit persistence-kit credential-kit utility-kit

all: $(ALL_OBJ)

process-kit: $(PROCESS_OBJ)
amsi-etw-kit: $(AMSI_ETW_OBJ)
persistence-kit: $(PERSIST_OBJ)
credential-kit: $(CRED_OBJ)
utility-kit: $(UTIL_OBJ)

# ── Build rules ──
# Each .c compiles to a relocatable object (.o) = BOF

$(OUTDIR)/%.o: src/process-kit/%.c | $(OUTDIR)
	@echo "-> BOF $(ARCH) $<"
	$(CC) $(CFLAGS) -o $@ $<

$(OUTDIR)/%.o: src/amsi-etw-kit/%.c | $(OUTDIR)
	@echo "-> BOF $(ARCH) $<"
	$(CC) $(CFLAGS) -o $@ $<

$(OUTDIR)/%.o: src/persistence-kit/%.c | $(OUTDIR)
	@echo "-> BOF $(ARCH) $<"
	$(CC) $(CFLAGS) -o $@ $<

$(OUTDIR)/%.o: src/credential-kit/%.c | $(OUTDIR)
	@echo "-> BOF $(ARCH) $<"
	$(CC) $(CFLAGS) -o $@ $<

$(OUTDIR)/%.o: src/utility-kit/%.c | $(OUTDIR)
	@echo "-> BOF $(ARCH) $<"
	$(CC) $(CFLAGS) -o $@ $<

$(OUTDIR):
	@mkdir -p $(OUTDIR)

clean:
	rm -rf bin/
