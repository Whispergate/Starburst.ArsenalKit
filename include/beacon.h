/*
 * beacon.h — Starburst BOF compatibility header
 *
 * Provides the Beacon API shim for BOFs executed via execute_coff.
 * The agent resolves these symbols at runtime and patches the
 * BOF's import table before calling go().
 */

#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#ifdef BOF
    #ifdef __cplusplus
    extern "C" {
    #endif

    /* ── Data parser ── */
    typedef struct {
        char* original;
        char* buffer;
        int   length;
        int   size;
    } datap;

    DECLSPEC_IMPORT void    BeaconDataParse(datap* parser, char* buffer, int size);
    DECLSPEC_IMPORT int     BeaconDataInt(datap* parser);
    DECLSPEC_IMPORT short   BeaconDataShort(datap* parser);
    DECLSPEC_IMPORT int     BeaconDataLength(datap* parser);
    DECLSPEC_IMPORT char*   BeaconDataExtract(datap* parser, int* size);

    /* ── Output ── */
    DECLSPEC_IMPORT void    BeaconPrintf(int type, char* fmt, ...);
    DECLSPEC_IMPORT void    BeaconOutput(int type, char* data, int len);

    /* ── Token ── */
    DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
    DECLSPEC_IMPORT void    BeaconRevertToken(void);
    DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);

    /* ── Process ── */
    typedef struct {
        char* original;
        char* buffer;
        int   length;
        int   size;
    } formatp;

    DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp* format, int maxsz);
    DECLSPEC_IMPORT void    BeaconFormatReset(formatp* format);
    DECLSPEC_IMPORT void    BeaconFormatFree(formatp* format);
    DECLSPEC_IMPORT void    BeaconFormatAppend(formatp* format, char* text, int len);
    DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp* format, char* fmt, ...);
    DECLSPEC_IMPORT char*   BeaconFormatToString(formatp* format, int* size);
    DECLSPEC_IMPORT void    BeaconFormatInt(formatp* format, int value);

    /* ── Spawn ── */
    DECLSPEC_IMPORT BOOL    BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                STARTUPINFOA* si, PROCESS_INFORMATION* pi);
    DECLSPEC_IMPORT void    BeaconInjectProcess(HANDLE hProc, int pid, char* payload,
                                int payloadLen, int offset, char* arg, int argLen);
    DECLSPEC_IMPORT void    BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pi,
                                char* payload, int payloadLen, int offset,
                                char* arg, int argLen);
    DECLSPEC_IMPORT void    BeaconCleanupProcess(PROCESS_INFORMATION* pi);

    /* ── Misc ── */
    DECLSPEC_IMPORT BOOL    BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
    DECLSPEC_IMPORT void    BeaconInjectProcess(HANDLE hProc, int pid, char* payload,
                                int p_len, int p_offset, char* arg, int a_len);

    /* ── Output types ── */
    #define CALLBACK_OUTPUT      0x00
    #define CALLBACK_OUTPUT_OEM  0x1e
    #define CALLBACK_ERROR       0x0d

    #ifdef __cplusplus
    }
    #endif
#endif /* BOF */

/* ── DFR macros for clean API imports ── */
#define DFR(module, function) \
    DECLSPEC_IMPORT WINBASEAPI typeof(function) module##$##function;
#define DFR_LOCAL(module, function) \
    typeof(function) * function = (typeof(function) *) module##$##function;

#endif /* BEACON_H */
