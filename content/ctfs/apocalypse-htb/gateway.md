+++
date = '2025-06-17T19:41:23+01:00'
draft = false
title = 'Rev/gateway'
hideToc = false
+++
# FIRST CHALLENGE: Gateway

## Challenge Description

Malakar has ensnared you with a dark spell, banishing you to the depths of the Nether world. Escape hinges on recalling the ancient enchantments of your forefathers. Wield their arcane power to shatter the Aether gateways and reclaim your freedom. Only the correct incantation—32 bytes of mystical precision—will unlock the path back to the mortal realm. Can you decipher the spell and blast through the barriers of this infernal trap?

![Challenge Image](./challengepic.png)

**Author:** 4ymen  
**Flag:** `HTB{r3tf@r_t0_tH3_h3@V3n5g@t3!!}`

---

## Challenge Difficulty

**Difficulty:** Hard

---

## Step 1: Analyzing the Entry Point (`0x8049d18`)

First, I ran the binary in `gdb` and set a breakpoint on the `write` syscall to track the code after the input prompt. This allowed me to dynamically determine the `read` syscall.

We started by examining the assembly at `0x8049d18`:

```asm
08049d18: popfd
08049d19: popad
08049d1a: mov eax, [ebp-0x1a4]         # Load length or counter
08049d20: mov [ebp-0x1c0], eax         # Store at ebp-0x1c0
08049d26: cmp dword ptr [ebp-0x1c0], 0x21  # Check if length == 33
08049d2d: jnz 0x8049f34                # If not 33, fail
08049d33: mov eax, [ebp-0x1c0]         # eax = 33
08049d39: sub eax, 0x1                 # eax = 32
08049d3c: mov byte ptr [ebp+eax-0x9d], 0  # Null-terminate at ebp-0x9c+32
08049d44: sub dword ptr [ebp-0x1c0], 0x1  # Length = 32
```

### Observations

- The code checks if a value at `$ebp-0x1a4` (likely input length) equals `0x21` (33 decimal). If not, it jumps to `0x8049f34` (failure path).
- It then subtracts 1 to get 32, null-terminates the input at `$ebp-0x9c + 32`, and updates `$ebp-0x1c0` to 32.

### Insights

- The input is 33 bytes (including a newline from stdin), but only 32 bytes are processed—suggesting a 32-byte flag plus `\n`.

We hypothesized `$ebp-0x9c` holds the input buffer, as it’s manipulated here. To confirm, we’d need to see where `$ebp-0x1a4` gets set (likely from an earlier `read` or `gets`), but this gave us a starting point.

---

## Step 2: Identifying the Hashing Loop

Next, we spotted a loop-like structure further down:

```asm
08049e0f: mov dword ptr [ebp-0x1c8], 0x0  # j = 0
08049e19: jmp 0x8049e9a
08049e1b: lea edx, [ebp-0x9c]          # Input buffer
08049e21: mov eax, [ebp-0x1c8]         # j
08049e27: add eax, edx                 # &input[j]
08049e29: mov [ebp-0x1bc], eax         # Param: pointer
08049e2f: mov dword ptr [ebp-0x1b8], 0x1  # Length = 1
08049e76: call 0x804996d               # Hash single byte
08049e93: addl $0x1, [ebp-0x1c8]       # j++
08049e9a: mov eax, [ebp-0x1c8]         # j
08049ea0: cmp eax, [ebp-0x1c0]         # j < 32
08049ea6: jl 0x8049e1b                 # Loop if j < 32
```

### Observations

- `$ebp-0x1c8` is a counter (`j`) initialized to 0, looping until it reaches `$ebp-0x1c0` (32).
- For each iteration:
    - It loads a byte from `$ebp-0x9c + j` (`input[j]`).
    - Passes a pointer to it (`$ebp-0x1bc`) and length 1 (`$ebp-0x1b8`) to `0x804996d`.

### Insights

- This is the hashing loop! Each of the 32 input bytes is hashed individually via `0x804996d`. The result likely builds an array of hashes.

We noted `0x804996d` calls `0x804a151` (the core hash function), but first, we needed to see where these hashes go.

---

## Step 3: Tracking Hash Storage

After the hash call:

```asm
08049e80: mov [ebp-0x1a4], edx         # Hash result
08049e86: mov eax, [ebp-0x1c8]         # j
08049e8c: mov [ebp+eax*4-0x19c], edx   # Store at ebp-0x19c + j*4
08049e93: addl $0x1, [ebp-0x1c8]       # j++
```

### Observations

- The hash result in `edx` is stored at `$ebp-0x19c + j*4`. With `j` from 0 to 31, this fills a 32-word (128-byte) array starting at `$ebp-0x19c`.

### Insights

- `$ebp-0x19c` holds the computed hashes of our input, one 32-bit hash per byte.

To confirm, we’d expect 32 iterations, matching the 32-byte flag length.

---

## Step 4: Finding the Comparison

The next critical section was the comparison logic at `0x8049eac`:

```asm
08049eac: mov byte ptr [ebp-0x1cd], 0x1  # Success flag = 1
08049eb3: mov dword ptr [ebp-0x1c4], 0x0  # i = 0
08049ebf: movzx ecx, byte ptr [ebp-0x1cd]  # Flag
08049ec6: mov eax, [ebp-0x1c4]         # i
08049ecc: mov edx, [ebp+eax*4-0x19c]  # Computed hash
08049ed9: mov eax, [ebp+eax*4-0x11c]  # Expected hash
08049ee0: cmp edx, eax                 # Compare
08049ee2: setz al                      # 1 if equal
08049ee8: and eax, ecx                 # flag &= equal
08049eef: mov [ebp-0x1cd], al          # Update flag
08049ef5: add dword ptr [ebp-0x1c4], 0x1
08049efc: cmp dword ptr [ebp-0x1c4], 0x1f
08049f03: jle 0x8049ebf                # i <= 31
08049f05: cmp byte ptr [ebp-0x1cd], 0x0
08049f0c: jz 0x8049f37                 # If flag = 0, fail
08049f18: call puts                    # "ENCHANTMENT CORRECT..."
```

### Observations

- Initializes a flag (`$ebp-0x1cd`) to 1 and counter `i` (`$ebp-0x1c4`) to 0.
- Loops 32 times (`i` from 0 to 31):
    - Loads a computed hash from `$ebp-0x19c + i*4` into `edx`.
    - Loads an expected hash from `$ebp-0x11c + i*4` into `eax`.
    - Compares them, updating the flag to 0 if any mismatch occurs.
- If the flag is 0 at `0x8049f05`, jumps to failure (`0x8049f37`); otherwise, prints success.

### Insights

- `$ebp-0x19c` is our input’s computed hashes, and `$ebp-0x11c` is the expected hashed password. Both are 32-word arrays (128 bytes), matching the 32-byte flag.

---

## Step 5: Putting It Together

By this point, we’d traced the flow:

1. **Input:** Read into `$ebp-0x9c`, 33 bytes, processed as 32 after null-termination.
2. **Hashing:** Each byte hashed via `0x804996d` (`0x804a151`), stored at `$ebp-0x19c[j]`.
3. **Comparison:** `$ebp-0x19c` (computed) vs `$ebp-0x11c` (expected), 32 hashes each.

### Key Discovery

- `$ebp-0x19c`: Our input’s hashed values.
- `$ebp-0x11c`: The target hashed password we need to match.

We confirmed this dynamically in GDB:

```bash
gdb -q ./gateway
(gdb) break *0x8049f05
(gdb) run < <(printf "HTB{AAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
(gdb) x/32xw $ebp-0x19c  # Computed hashes
(gdb) x/32xw $ebp-0x11c  # Expected hashes
```

This showed `$ebp-0x19c` differing from `$ebp-0x11c`, with `$ebp-0x1cd = 0`, proving the mismatch. The expected hashes at `$ebp-0x11c` became our target to reverse.

---

## Next Steps: Cracking the Hash

### Step 6: Building a Hash Map

Since the hash function is deterministic, I sent every printable character as input (repeated 32 times to match the required length) and captured the hashed values. This allowed me to build a hash map of characters to their corresponding hash values.

Here is the hash map I generated: [hash_map_chars.json](./hash_map_chars.json).

### Step 7: Observing Character Swapping

Upon analyzing the results, I discovered that the hash function swaps characters before hashing them. For example, the input `"ghHr3f35V_t3_nB@t}Hr@!T3tt!_{0"` produced unexpected hash values due to this swapping mechanism. This made it clear that a simple hash map wouldn't suffice.

### Step 8: Dynamic Analysis with a Script

To address this, I wrote a script to dynamically analyze the hashing process. The script sends input to the binary, examines the hashed values at `$ebp-0x19c`, and modifies one character at a time while keeping the others fixed. By observing which hash value changes, I could map each character to its transformed hash.

Here is the script I used: [solver.py](./solver.py).
```python
#!/usr/bin/env python3
import pexpect
import re
import sys
import traceback
import json

def run_gdb_interaction(binary_path, password):
    try:
        # Spawn GDB process with verbose output
        gdb = pexpect.spawn(f'gdb {binary_path}', encoding='utf-8', logfile=sys.stdout)
        gdb.timeout = 10
        
        # Set breakpoint
        gdb.sendline('break *0x08049f05')
        
        # Run the program
        gdb.sendline('run')
        
        # Wait for program prompts or events
        while True:
            index = gdb.expect([
                'Breakpoint 1, ', 
                'Recall the ✨ enchantments ✨ of your forefathers: ', 
                'Program received signal', 
                'No such file or directory',
                pexpect.TIMEOUT, 
                pexpect.EOF
            ])
            
            if index == 0:
                print(f"[DEBUG] Breakpoint hit with password: {password}")
                break
            elif index == 1:
                print(f"[DEBUG] Sending password: {password}")
                gdb.sendline(password)
                break
            elif index in [2, 3, 4, 5]:
                print(f"[DEBUG] Unexpected event. Index: {index}")
                gdb.close()
                return None
        
        gdb.expect_exact("(gdb)")
        # Examine memory location
        gdb.sendline('x/32xw $ebp-0x19c')
        gdb.expect_exact("(gdb)")
        memory_output = gdb.before
        gdb.sendline('x/32xw $ebp-0x11c')
        gdb.expect_exact("(gdb)")
        flag_output = gdb.before
                
        # Quit GDB
        gdb.sendline('quit')
        gdb.close()
        
        return parse_memory_output(memory_output),parse_memory_output(flag_output)

    except Exception as e:
        print("[DEBUG] Unexpected error:")
        print(traceback.format_exc())
        return None

def parse_memory_output(output):
    memory_values = []
    
    for line in output.splitlines():
        match = re.search(r':\s*(.*)', line)
        if match:
            values = match.group(1).split()
            memory_values.extend(values)
    
    return memory_values

def map_character_transformations(binary_path):
    # Initial password with all 'A's
    base_password = 'HTB{' + 'A' * 27 + '}'
    
    # Dictionary to store character transformations
    transformation_map = {}
    
    # Iterate through each position to map
    for pos in range(len(base_password)):  # Skip 'HTB{' and '}'
        print(f"\n[DEBUG] Mapping transformations for position {pos}")
        
        # Prepare passwords with A and B at the current position
        a_password = list(base_password)
        b_password = list(base_password)
        a_password[pos] = 'A'
        b_password[pos] = 'B'
        
        # Convert to strings
        a_password_str = ''.join(a_password)
        b_password_str = ''.join(b_password)
        
        # Get memory values for A and B
        a_memory,flag_output1 = run_gdb_interaction(binary_path, a_password_str)
        b_memory,flag_output2 = run_gdb_interaction(binary_path, b_password_str)
        
        if a_memory is None or b_memory is None:
            print(f"[ERROR] Failed to get memory for position {pos}")
            continue
        j=0;
        for i in  range(len(a_memory)):
            if a_memory[i]!=b_memory[i]:
                j=i;
                
        # Find indices where memory differs
        different_indices = j;
        
        # Store transformation details
        transformation_map[pos] = {
            'changed_indices': different_indices,
            'a_values': a_memory[j] ,
            'b_values': b_memory[j],
            'you_have_to_match':flag_output1[j],
            'you_have_to_match2':flag_output2[j],
            
        }
        

    
    return transformation_map

def main():
    binary_path = "./gateway"  # Replace with actual binary path
    
    # Map character transformations
    transformation_map = map_character_transformations(binary_path)
    
    # Write the transformation map to a JSON file
    with open('transformation_map.json', 'w') as json_file:
        json.dump(transformation_map, json_file, indent=4)
    # Print summary
    print("\n[SUMMARY] Transformation Map:")
    for pos, details in transformation_map.items():
        print(f"Position {pos}:")
        print(f"  Changed Indices: {details['changed_indices']}")
        print(f"  A Values: {details['a_values']}")
        print(f"  B Values: {details['b_values']}")

if __name__ == "__main__":
    main()
```
### Step 9: Generating a Transformation Map

Using the script, I built a transformation map that accounts for the character swapping and hashing behavior. The resulting transformation map is available here: [transformation_map.json](rev/gateway/transformation_map.json).
```json
{
    "0": {
        "changed_indices": 20,
        "a_values": "0x1ba09040",
        "b_values": "0xb0476f74",
        "you_have_to_match": "0x4c6f6e28",
        "you_have_to_match2": "0x4c6f6e28"
    },
   ..........,
    "28": {
        "changed_indices": 11,
        "a_values": "0x1ba09040",
        "b_values": "0xb0476f74",
        "you_have_to_match": "0x3cd56ab6",
        "you_have_to_match2": "0x3cd56ab6"
    },
    "29": {
        "changed_indices": 23,
        "a_values": "0x1ba09040",
        "b_values": "0xb0476f74",
        "you_have_to_match": "0x9d14f94b",
        "you_have_to_match2": "0x9d14f94b"
    },
    "30": {
        "changed_indices": 28,
        "a_values": "0x1ba09040",
        "b_values": "0xb0476f74",
        "you_have_to_match": "0x9d14f94b",
        "you_have_to_match2": "0x9d14f94b"
    },
    "31": {
        "changed_indices": 19,
        "a_values": "0x1ba09040",
        "b_values": "0xb0476f74",
        "you_have_to_match": "0xe864d8ce",
        "you_have_to_match2": "0xe864d8ce"
    }
}
```

### Step 10: Reversing the Hash

Finally, I wrote a script to reverse the hash using the transformation map. This script reconstructs the original input that matches the expected hash values.

Here is the script for reversing the hash: [flagprinter.py](./flagprinter.py).
```python
flag=[]
for i in range(32):
    for key, value in chars.items():
        if value == matched[str(i)]["you_have_to_match"]:
            print(key)
            flag.append(key)
print(''.join(flag))
```
---

## Conclusion

By combining dynamic analysis and problem-solving, I successfully reversed the hash and retrieved the flag. The process involved understanding the binary's behavior, building a hash map, accounting for character transformations, and finally reversing the hash to obtain the solution. GG!

