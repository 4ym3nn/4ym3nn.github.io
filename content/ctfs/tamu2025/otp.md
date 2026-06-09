+++
date = '2025-06-17T22:29:05+01:00'
draft = false
title = 'otp'
+++

# tamu2025 - rev Challenge: otp

## Description

This challenge involves reverse engineering and cryptographic analysis to extract keys and decrypt an encrypted flag. The solution uses GDB scripting to automate the extraction of keys from memory frames and applies XOR decryption to retrieve the original flag.

## Solution

### GDB Script: ExtractKeys

The following GDB script automates the extraction of keys from memory frames:

```python
import gdb
import re

class ExtractKeys(gdb.Command):
    def __init__(self):
        super(ExtractKeys, self).__init__("extract_keys", gdb.COMMAND_USER)

    def parse_gdb_line(self, line):
        """
        Extracts byte values from a single line of GDB output.
        Example input: "0x7ffe603d0100: 0x45 0x65 0x41 0x15 0x57 0xc0 0xdb 0xda"
        Returns: ["45", "65", "41", "15", "57", "c0", "db", "da"]
        """
        match = re.search(r":\s+((?:0x[0-9a-f]{2}\s*)+)", line)
        if match:
            return re.findall(r"0x([0-9a-f]{2})", match.group(1))
        return []

    def parse_gdb_output(self, gdb_output):
        """
        Parses the entire GDB output to extract key bytes.
        Returns a single hex string.
        """
        key_bytes = []
        for line in gdb_output.split("\n"):
            key_bytes.extend(self.parse_gdb_line(line))
        return "".join(key_bytes)

    def invoke(self, arg, from_tty):
        start_frame, end_frame = 4, 1003
        with open("keys.txt", "w") as key_file:
            for frame_id in range(start_frame, end_frame + 1):
                try:
                    gdb.execute(f"frame {frame_id}", to_string=True)
                    key_output = gdb.execute(f"x/59bx key", to_string=True)
                    key_hex_string = self.parse_gdb_output(key_output)
                    if key_hex_string:
                        key_file.write(key_hex_string + "\n")
                except gdb.error:
                    print(f"[-] Skipping frame {frame_id} (No key found)")
                    continue
        print("[✔] All keys extracted to keys.txt")

ExtractKeys()
```

### Decryption Process

The decryption process involves loading the encrypted flag and the extracted keys, then applying XOR decryption in reverse order:

```python
# Load the encrypted flag as a hex string
with open("encrypted_flag.bin", "rb") as f:
    encrypted_flag = f.read().hex()

# Load all 1000 keys from keys.txt as strings
with open("keys.txt", "r", encoding="utf-8") as f:
    keys = [line.strip() for line in f]

# Ensure all keys are unique (sanity check)
assert len(keys) == len(set(keys)), "Duplicate keys detected!"

# Ensure key lengths match encrypted flag length
flag_length = len(encrypted_flag) // 2
print(f"[INFO] Encrypted flag length: {flag_length} bytes")

# Reverse the encryption process by applying XOR in reverse order
for key in reversed(keys):
    key_bytes = bytes.fromhex(key)
    assert len(key_bytes) == flag_length, f"Key length mismatch: Expected {flag_length}, got {len(key_bytes)}"
    encrypted_flag = bytes(a ^ b for a, b in zip(bytes.fromhex(encrypted_flag), key_bytes)).hex()

# Convert final decrypted hex to a string
decrypted_flag = bytes.fromhex(encrypted_flag).decode(errors="ignore")

print(f"[+] Decrypted Flag: {decrypted_flag}")
```

### Flag

The decrypted flag is:

```
gigem{if_you_did_that_manually_i_am_so_sorry_for_your_loss}
```
