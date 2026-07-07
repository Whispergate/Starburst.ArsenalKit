/*
 * hashGenerator - Starburst FNV-1a hash generator utility.
 *
 * Standalone utility that computes FNV-1a hashes matching Starburst's
 * expr::hash_string implementation (case-insensitive).
 *
 * USAGE:
 *   hashGenerator.exe [-w] string1 string2 ...
 *
 *   -w    Compute wide string hash (for module names like L"ntdll.dll")
 *         Default is narrow string hash (for function names like "NtDelayExecution")
 *
 * EXAMPLES:
 *   hashGenerator.exe NtDelayExecution NtAllocateVirtualMemory
 *   hashGenerator.exe -w ntdll.dll kernel32.dll
 *   hashGenerator.exe -w NTDLL.DLL ntdll.dll
 *
 * OUTPUT FORMAT:
 *   "string" = 0xDEADBEEF
 *
 * HASH ALGORITHM:
 *   FNV-1a with seed 0x811c9dc5 and prime 0x01000193.
 *   Each byte is uppercased (toupper) before XOR into the hash.
 *   Wide mode: each wchar_t is cast to unsigned short then unsigned char
 *   (low byte only), matching Starburst's expr::hash_string<wchar_t>.
 *
 * BUILD:
 *   cl.exe /nologo /O2 hashGenerator.c /Fe:hashGenerator.exe
 *   or:
 *   x86_64-w64-mingw32-gcc -O2 hashGenerator.c -o hashGenerator.exe
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long DWORD;

/* FNV-1a narrow string hash matching Starburst's expr::hash_string (case-insensitive) */
static DWORD fnv1a_hash(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        unsigned char byte = (unsigned char)*str++;
        if (byte >= 'a')
            byte -= 0x20;
        hash ^= byte;
        hash *= 0x01000193;
    }
    return hash;
}

/*
 * FNV-1a wide string hash matching Starburst's expr::hash_string<wchar_t>.
 *
 * In the agent, wchar_t characters are cast to unsigned char (low byte only)
 * before hashing. We simulate this by treating each char of the input as if
 * it were the low byte of a wchar_t, which is identical for ASCII strings.
 */
static DWORD fnv1a_hash_wide(const char* str) {
    DWORD hash = 0x811c9dc5;
    while (*str) {
        /* Simulate: (unsigned char)(unsigned short)wchar_t */
        unsigned char byte = (unsigned char)*str++;
        if (byte >= 'a')
            byte -= 0x20;
        hash ^= byte;
        hash *= 0x01000193;
    }
    return hash;
}

static void print_usage(const char* prog) {
    printf("Starburst hashGenerator - FNV-1a hash generator utility\n\n");
    printf("Usage: %s [-w] string1 [string2 ...]\n\n", prog);
    printf("Options:\n");
    printf("  -w    Compute wide string hash (for module names like L\"ntdll.dll\")\n");
    printf("        Default: narrow string hash (for function names)\n\n");
    printf("Hash algorithm: FNV-1a, seed 0x811c9dc5, prime 0x01000193, case-insensitive\n\n");
    printf("Examples:\n");
    printf("  %s NtDelayExecution NtAllocateVirtualMemory\n", prog);
    printf("  %s -w ntdll.dll kernel32.dll\n", prog);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int wide_mode = 0;
    int start_idx = 1;

    if (strcmp(argv[1], "-w") == 0) {
        wide_mode = 1;
        start_idx = 2;
    }

    if (start_idx >= argc) {
        fprintf(stderr, "Error: no strings provided.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("Mode: %s string hash (FNV-1a, case-insensitive)\n\n",
           wide_mode ? "wide" : "narrow");

    for (int i = start_idx; i < argc; i++) {
        DWORD hash;
        if (wide_mode) {
            hash = fnv1a_hash_wide(argv[i]);
            printf("  L\"%s\" = 0x%08lx\n", argv[i], hash);
        } else {
            hash = fnv1a_hash(argv[i]);
            printf("  \"%s\" = 0x%08lx\n", argv[i], hash);
        }
    }

    printf("\n");
    return 0;
}
