CC       = x86_64-w64-mingw32-gcc
CFLAGS   = -c -Os -fno-asynchronous-unwind-tables -fpack-struct=8 -pipe -w
INCLUDES = -I../common/include -Iprofiles

# Mask type: MASK_EKKO=0, MASK_FULL_IMAGE=1, MASK_HEAP=2
MASK_TYPE   ?= 0
ENABLE_CFG  ?= 1
ENABLE_HEAP ?= 1

DEFINES  = -DMASK_TYPE=$(MASK_TYPE) -DENABLE_CFG=$(ENABLE_CFG) -DENABLE_HEAP=$(ENABLE_HEAP)

all: bin/mask.x64.o

bin/mask.x64.o: src/mask.c ../common/include/pic_defs.h ../common/include/user_data.h ../common/include/cfg_bypass.h
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $<

clean:
	rm -f bin/mask.x64.o
