/*
 * enum_pipes.c - Enumerate named pipes on the system
 *
 * Uses FindFirstFileA / FindNextFileA on \\.\pipe\* to list
 * all named pipes currently present. Optionally filters by a
 * substring if one is provided as an argument.
 *
 * Args: [optional] filter string - only pipes containing this
 *       substring (case-insensitive) are printed
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── DFR imports ── */
DFR(KERNEL32, FindFirstFileA)
DFR(KERNEL32, FindNextFileA)
DFR(KERNEL32, FindClose)
DFR(MSVCRT, _stricmp)
DFR(MSVCRT, strlen)

/*
 * Simple case-insensitive substring search.
 * Returns non-zero if needle is found in haystack.
 */
static int stristr(const char* haystack, const char* needle)
{
    if (!needle || !needle[0]) return 1;
    for (; *haystack; haystack++) {
        const char* h = haystack;
        const char* n = needle;
        while (*h && *n) {
            char hc = *h;
            char nc = *n;
            /* tolower inline - avoid extra DFR for ctype */
            if (hc >= 'A' && hc <= 'Z') hc += 32;
            if (nc >= 'A' && nc <= 'Z') nc += 32;
            if (hc != nc) break;
            h++;
            n++;
        }
        if (!*n) return 1;
    }
    return 0;
}

void go(char* args, int len)
{
    /* Parse optional filter argument */
    char* filter    = NULL;
    int   filterLen = 0;

    if (args != NULL && len > 0) {
        datap parser;
        BeaconDataParse(&parser, args, len);
        filter = BeaconDataExtract(&parser, &filterLen);
        if (filterLen <= 1) {
            filter = NULL; /* empty string or just null terminator */
        }
    }

    /* Enumerate pipes via FindFirstFile / FindNextFile */
    WIN32_FIND_DATAA fd;
    HANDLE hFind = KERNEL32$FindFirstFileA("\\\\.\\pipe\\*", &fd);

    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "enum_pipes: FindFirstFileA failed (err %lu)",
                     GetLastError());
        return;
    }

    /* Collect output in a format buffer */
    formatp fmt;
    BeaconFormatAlloc(&fmt, 64 * 1024); /* 64 KB should be plenty */
    int count    = 0;
    int filtered = 0;

    do {
        if (filter != NULL) {
            if (!stristr(fd.cFileName, filter)) {
                continue;
            }
            filtered++;
        }
        BeaconFormatPrintf(&fmt, "\\\\.\\pipe\\%s\n", fd.cFileName);
        count++;
    } while (KERNEL32$FindNextFileA(hFind, &fd));

    KERNEL32$FindClose(hFind);

    /* Summary line */
    if (filter != NULL) {
        BeaconFormatPrintf(&fmt, "\n%d pipes matched filter \"%s\"", count, filter);
    } else {
        BeaconFormatPrintf(&fmt, "\nTotal: %d named pipes", count);
    }

    int   outputLen = 0;
    char* output    = BeaconFormatToString(&fmt, &outputLen);
    BeaconOutput(CALLBACK_OUTPUT, output, outputLen);

    BeaconFormatFree(&fmt);
}
