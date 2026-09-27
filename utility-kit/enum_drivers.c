/*
 * enum_drivers.c - Enumerate loaded kernel drivers via NtQuerySystemInformation
 *
 * Queries SystemModuleInformation (class 11) to list every loaded
 * kernel module with base address, image size, and file name.
 *
 * Args: none
 */

#include <windows.h>

#define BOF
#include "beacon.h"

/* ── NT type definitions ── */
typedef LONG NTSTATUS;
#define NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG                          NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

/* ── NT function prototype ── */
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

/* ── DFR imports ── */
DFR(KERNEL32, GetModuleHandleA)
DFR(KERNEL32, GetProcAddress)
DFR(MSVCRT, malloc)
DFR(MSVCRT, free)
DFR(MSVCRT, memset)

void go(char* args, int len)
{
    /* Resolve NtQuerySystemInformation from ntdll */
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "enum_drivers: failed to get ntdll handle");
        return;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)KERNEL32$GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "enum_drivers: failed to resolve NtQuerySystemInformation");
        return;
    }

    /* Query required buffer size */
    ULONG    bufSize = 0;
    NTSTATUS status  = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufSize);
    if (bufSize == 0) {
        BeaconPrintf(CALLBACK_ERROR, "enum_drivers: NtQuerySystemInformation returned zero size");
        return;
    }

    /* Allocate and query */
    bufSize += 0x1000; /* pad for race conditions */
    PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)MSVCRT$malloc(bufSize);
    if (pModules == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "enum_drivers: malloc(%lu) failed", bufSize);
        return;
    }

    MSVCRT$memset(pModules, 0, bufSize);
    status = NtQuerySystemInformation(SystemModuleInformation, pModules, bufSize, &bufSize);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "enum_drivers: NtQuerySystemInformation failed (0x%08X)", status);
        MSVCRT$free(pModules);
        return;
    }

    /* Format output using BeaconFormatAlloc for efficiency */
    formatp fmt;
    BeaconFormatAlloc(&fmt, pModules->NumberOfModules * 120 + 256);
    BeaconFormatPrintf(&fmt, "%-18s  %-10s  %s\n", "Base", "Size", "Driver Name");
    BeaconFormatPrintf(&fmt, "%-18s  %-10s  %s\n", "------------------", "----------", "----------------------------");

    for (ULONG i = 0; i < pModules->NumberOfModules; i++) {
        RTL_PROCESS_MODULE_INFORMATION* mod = &pModules->Modules[i];
        char* fileName = (char*)&mod->FullPathName[mod->OffsetToFileName];

        BeaconFormatPrintf(&fmt, "0x%p  0x%08X  %s\n",
                           mod->ImageBase,
                           mod->ImageSize,
                           fileName);
    }

    BeaconFormatPrintf(&fmt, "\nTotal: %lu loaded kernel modules", pModules->NumberOfModules);

    int    outputLen = 0;
    char*  output    = BeaconFormatToString(&fmt, &outputLen);
    BeaconOutput(CALLBACK_OUTPUT, output, outputLen);

    /* Cleanup */
    BeaconFormatFree(&fmt);
    MSVCRT$free(pModules);
}
