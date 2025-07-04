+++
date = '2025-06-17T22:29:05+01:00'
draft = false
title = 'xorox'
+++

# tamu2025 - rev Challenge: xorox

## Description

This challenge involves reverse engineering a binary to determine the required input that produces the desired output. The solution involves XOR operations and understanding the binary's constants and register values.

## Solution

The following Python script demonstrates the solution:

```python
import struct

# Constants from the binary
constant = [
    0x2a8c7f3acdf36ffb,  # First 8 bytes of the constant
    0x8cc2eef32660caaa,  # Next 8 bytes
    0xefa1fd61d7a3b592,  # Next 8 bytes
    0xa9ddc2d22a90025e   # Last 8 bytes
]

# YMM7 register values from GDB (converted to 4x 64-bit integers)
ymm7 = [
    0x1eca2043bfc01980,
    0xd386a3ba753fbe9f,
    0x87d5cc1688d185ea,
    0xd4aebbb741cf3001
]

def qwords_to_bytes(qwords):
    return b''.join(struct.pack('<Q', q) for q in qwords)

constant_bytes = qwords_to_bytes(constant)
ymm7_bytes = qwords_to_bytes(ymm7)

required_input = bytes(a ^ b for a, b in zip(constant_bytes, ymm7_bytes))

flag = b"gigem" + required_input

print("Raw bytes:", flag)

# Try to decode as ASCII (some bytes may not be printable)
try:
    print("ASCII:", flag.decode('ascii'))
except UnicodeDecodeError:
    print("Contains non-ASCII bytes")
```

## Flag

The flag for this challenge is:

```
gigem{v3ry_F45t_SIMD_x0r_w1th_2_keys}
```
