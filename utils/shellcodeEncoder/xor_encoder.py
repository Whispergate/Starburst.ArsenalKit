#!/usr/bin/env python3
"""
xor_encoder.py - Starburst Arsenal Kit XOR shellcode encoder.

XOR-encodes a raw shellcode .bin file with a repeating key.

Usage:
    python xor_encoder.py input.bin output.bin [key_hex]

Arguments:
    input.bin   - Raw shellcode file to encode
    output.bin  - Output file for encoded shellcode
    key_hex     - Optional XOR key in hex (e.g. deadbeef0102030405060708090a0b0c)
                  Default: random 16-byte key

Output:
    - Encoded .bin file written to output path
    - XOR key printed in hex
    - Decoder stubs printed in C, PowerShell, and Python formats
    - Encoded shellcode printed as C and PowerShell byte arrays

Examples:
    python xor_encoder.py beacon.bin beacon_xor.bin
    python xor_encoder.py payload.bin payload_xor.bin aabbccdd11223344
"""

import sys
import os


def xor_encode(data: bytes, key: bytes) -> bytes:
    """XOR encode data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


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


def print_decoder_stubs(key: bytes):
    """Print XOR decoder stubs in C, PowerShell, and Python."""
    key_len = len(key)

    # C decoder stub
    print("=" * 60)
    print("C DECODER STUB")
    print("=" * 60)
    c_key = ", ".join(f"0x{b:02x}" for b in key)
    print(f"""
unsigned char key[] = {{ {c_key} }};
unsigned int key_len = {key_len};

void xor_decode(unsigned char* data, unsigned int data_len) {{
    for (unsigned int i = 0; i < data_len; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}

/* Usage: xor_decode(shellcode, shellcode_len); */
""")

    # PowerShell decoder stub
    print("=" * 60)
    print("POWERSHELL DECODER STUB")
    print("=" * 60)
    ps_key = ", ".join(f"0x{b:02X}" for b in key)
    print(f"""
[Byte[]] $key = @( {ps_key} )

for ($i = 0; $i -lt $shellcode.Length; $i++) {{
    $shellcode[$i] = $shellcode[$i] -bxor $key[$i % $key.Length]
}}
""")

    # Python decoder stub
    print("=" * 60)
    print("PYTHON DECODER STUB")
    print("=" * 60)
    py_key = "".join(f"\\x{b:02x}" for b in key)
    print(f"""
key = b"{py_key}"

def xor_decode(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

decoded = xor_decode(shellcode, key)
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

    # Encode
    encoded = xor_encode(shellcode, key)

    # Write output
    with open(output_file, "wb") as f:
        f.write(encoded)

    # Print results
    print(f"[*] Input:    {input_file} ({len(shellcode)} bytes)")
    print(f"[*] Output:   {output_file} ({len(encoded)} bytes)")
    print(f"[*] Key:      {key.hex()}")
    print(f"[*] Key size: {len(key)} bytes")
    print()

    # Print key formats
    print("=" * 60)
    print("XOR KEY")
    print("=" * 60)
    print(format_c_array(key, "xor_key"))
    print()
    print(format_ps_array(key, "xor_key"))
    print()
    print(format_python_bytes(key, "xor_key"))
    print()

    # Print decoder stubs
    print_decoder_stubs(key)

    # Print encoded shellcode arrays
    print("=" * 60)
    print("ENCODED SHELLCODE - C BYTE ARRAY")
    print("=" * 60)
    print(format_c_array(encoded, "shellcode"))
    print()

    print("=" * 60)
    print("ENCODED SHELLCODE - POWERSHELL BYTE ARRAY")
    print("=" * 60)
    print(format_ps_array(encoded, "shellcode"))
    print()

    print("=" * 60)
    print("ENCODED SHELLCODE - PYTHON BYTES")
    print("=" * 60)
    print(format_python_bytes(encoded, "shellcode"))
    print()

    # Verify round-trip
    decoded = xor_encode(encoded, key)
    if decoded == shellcode:
        print("[+] Verification: round-trip decode PASSED")
    else:
        print("[-] Verification: round-trip decode FAILED", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
