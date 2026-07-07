#!/usr/bin/env python3
"""
rc4_encoder.py - Starburst Arsenal Kit RC4 shellcode encoder.

RC4-encrypts a raw shellcode .bin file.

Usage:
    python rc4_encoder.py input.bin output.bin [key_hex]

Arguments:
    input.bin   - Raw shellcode file to encrypt
    output.bin  - Output file for encrypted shellcode
    key_hex     - Optional RC4 key in hex (e.g. deadbeef0102030405060708090a0b0c)
                  Default: random 16-byte key

Output:
    - Encrypted .bin file written to output path
    - RC4 key printed in hex
    - Decoder stub printed in C (suitable for embedding in a loader)
    - Encrypted shellcode printed as C, PowerShell, and Python byte arrays

Examples:
    python rc4_encoder.py beacon.bin beacon_rc4.bin
    python rc4_encoder.py payload.bin payload_rc4.bin aabbccdd11223344556677889900ffee
"""

import sys
import os


def rc4_init(key: bytes) -> list:
    """Initialize the RC4 S-box (KSA)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encrypt/decrypt data with key (PRGA)."""
    s = rc4_init(key)
    i = 0
    j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = data[k] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def format_c_array(data: bytes, name: str = "shellcode", line_width: int = 16) -> str:
    """Format bytes as a C unsigned char array."""
    lines = []
    lines.append(f"unsigned char {name}[] = {{")
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_vals = ", ".join(f"0x{b:02x}" for b in chunk)
        if i + line_width < len(data):
            hex_vals += ","
        lines.append(f"    {hex_vals}")
    lines.append("};")
    lines.append(f"unsigned int {name}_len = sizeof({name});")
    return "\n".join(lines)


def format_ps_array(data: bytes, name: str = "shellcode", line_width: int = 16) -> str:
    """Format bytes as a PowerShell byte array."""
    lines = []
    lines.append(f"[Byte[]] ${name} = @(")
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_vals = ", ".join(f"0x{b:02X}" for b in chunk)
        if i + line_width < len(data):
            hex_vals += ","
        lines.append(f"    {hex_vals}")
    lines.append(")")
    return "\n".join(lines)


def format_python_bytes(data: bytes, name: str = "shellcode", line_width: int = 16) -> str:
    """Format bytes as Python bytes literal."""
    lines = []
    lines.append(f"{name} = (")
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        hex_str = "".join(f"\\x{b:02x}" for b in chunk)
        lines.append(f'    b"{hex_str}"')
    lines.append(")")
    return "\n".join(lines)


def print_c_decoder_stub(key: bytes):
    """Print a complete C RC4 decoder stub suitable for embedding in a loader."""
    c_key = ", ".join(f"0x{b:02x}" for b in key)
    key_len = len(key)

    print("=" * 60)
    print("C RC4 DECODER STUB")
    print("=" * 60)
    print(f"""
unsigned char rc4_key[] = {{ {c_key} }};
unsigned int rc4_key_len = {key_len};

void rc4_decrypt(unsigned char* data, unsigned int data_len,
                 unsigned char* key, unsigned int key_len) {{
    unsigned char s[256];
    unsigned int i, j, k;
    unsigned char tmp;

    /* KSA */
    for (i = 0; i < 256; i++)
        s[i] = (unsigned char)i;
    j = 0;
    for (i = 0; i < 256; i++) {{
        j = (j + s[i] + key[i % key_len]) & 0xFF;
        tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }}

    /* PRGA */
    i = 0; j = 0;
    for (k = 0; k < data_len; k++) {{
        i = (i + 1) & 0xFF;
        j = (j + s[i]) & 0xFF;
        tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[k] ^= s[(s[i] + s[j]) & 0xFF];
    }}
}}

/* Usage: rc4_decrypt(shellcode, shellcode_len, rc4_key, rc4_key_len); */
""")


def print_ps_decoder_stub(key: bytes):
    """Print a PowerShell RC4 decoder stub."""
    ps_key = ", ".join(f"0x{b:02X}" for b in key)

    print("=" * 60)
    print("POWERSHELL RC4 DECODER STUB")
    print("=" * 60)
    print(f"""
[Byte[]] $rc4_key = @( {ps_key} )

function RC4-Decrypt([Byte[]]$data, [Byte[]]$key) {{
    [Byte[]] $s = 0..255
    [int] $j = 0
    for ([int] $i = 0; $i -lt 256; $i++) {{
        $j = ($j + $s[$i] + $key[$i % $key.Length]) -band 0xFF
        $tmp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $tmp
    }}
    $i = 0; $j = 0
    [Byte[]] $out = New-Object Byte[] $data.Length
    for ([int] $k = 0; $k -lt $data.Length; $k++) {{
        $i = ($i + 1) -band 0xFF
        $j = ($j + $s[$i]) -band 0xFF
        $tmp = $s[$i]; $s[$i] = $s[$j]; $s[$j] = $tmp
        $out[$k] = $data[$k] -bxor $s[($s[$i] + $s[$j]) -band 0xFF]
    }}
    return $out
}}

$decrypted = RC4-Decrypt $shellcode $rc4_key
""")


def print_python_decoder_stub(key: bytes):
    """Print a Python RC4 decoder stub."""
    py_key = "".join(f"\\x{b:02x}" for b in key)

    print("=" * 60)
    print("PYTHON RC4 DECODER STUB")
    print("=" * 60)
    print(f"""
rc4_key = b"{py_key}"

def rc4_decrypt(data, key):
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = data[k] ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)

decrypted = rc4_decrypt(shellcode, rc4_key)
""")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Read input shellcode
    if not os.path.isfile(input_file):
        print(f"Error: input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, "rb") as f:
        shellcode = f.read()

    if len(shellcode) == 0:
        print("Error: input file is empty.", file=sys.stderr)
        sys.exit(1)

    # Parse or generate key
    if len(sys.argv) >= 4:
        try:
            key = bytes.fromhex(sys.argv[3])
        except ValueError:
            print("Error: key must be valid hex (e.g. deadbeef0102030405060708090a0b0c).",
                  file=sys.stderr)
            sys.exit(1)
        if len(key) == 0:
            print("Error: key cannot be empty.", file=sys.stderr)
            sys.exit(1)
    else:
        key = os.urandom(16)

    # Encrypt
    encrypted = rc4_crypt(shellcode, key)

    # Write output
    with open(output_file, "wb") as f:
        f.write(encrypted)

    # Print results
    print(f"[*] Input:    {input_file} ({len(shellcode)} bytes)")
    print(f"[*] Output:   {output_file} ({len(encrypted)} bytes)")
    print(f"[*] Key:      {key.hex()}")
    print(f"[*] Key size: {len(key)} bytes")
    print()

    # Print key formats
    print("=" * 60)
    print("RC4 KEY")
    print("=" * 60)
    print(format_c_array(key, "rc4_key"))
    print()
    print(format_ps_array(key, "rc4_key"))
    print()
    print(format_python_bytes(key, "rc4_key"))
    print()

    # Print decoder stubs
    print_c_decoder_stub(key)
    print_ps_decoder_stub(key)
    print_python_decoder_stub(key)

    # Print encrypted shellcode arrays
    print("=" * 60)
    print("ENCRYPTED SHELLCODE - C BYTE ARRAY")
    print("=" * 60)
    print(format_c_array(encrypted, "shellcode"))
    print()

    print("=" * 60)
    print("ENCRYPTED SHELLCODE - POWERSHELL BYTE ARRAY")
    print("=" * 60)
    print(format_ps_array(encrypted, "shellcode"))
    print()

    print("=" * 60)
    print("ENCRYPTED SHELLCODE - PYTHON BYTES")
    print("=" * 60)
    print(format_python_bytes(encrypted, "shellcode"))
    print()

    # Verify round-trip
    decrypted = rc4_crypt(encrypted, key)
    if decrypted == shellcode:
        print("[+] Verification: round-trip decrypt PASSED")
    else:
        print("[-] Verification: round-trip decrypt FAILED", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
