+++
date = '2025-07-27T19:41:23+01:00'
draft = false
title = 'Nim Yong Un'
hideToc = false
+++

# WorldWideCTF 2025: rev/Nim Yong Un 

## Challenge Description

> Our agents captured some North Korean military software. Your task: find the correct launch code!

## Approach & Solution

## What We're Dealing With

I got my hands on this Windows PE binary that was asking for a 42-character flag. Right off the bat, I could tell this wasn't going to be your typical reverse engineering challenge when I threw some random input at it.

The binary had that distinct smell of being compiled from Nim – you know, all those weird function names like `nsuRepeatChar` and the garbage collector patterns. But what really caught my attention was the way string handling and memory management looked, which is pretty unique to Nim.

## Digging Into the Meat

When I loaded this thing into IDA, I found the main processing loop that immediately told me I was in for a ride:

```c
v5 = 42;  // Exactly 42 characters required
v6 = 0;
while ( 2 )
{
    // Grab character at current position
    v7 = (unsigned int)*(char *)(*((_QWORD *)&flag__chal_u498 + 1) + v6 + 8);

    // This is where things get interesting
    nsuRepeatChar(&si128, v7, 69);

    // Then it does some MD5 magic
    md5Sum__chal_u47(&si128, &iv__chal_u508, &digest__chal_u672);

    // And updates something for the next round
    iv__chal_u508 = (__int128)_mm_load_si128((const __m128i *)&digest__chal_u672);
}
```

The first thing that jumped out was that `nsuRepeatChar` function. After some digging, I figured out it takes whatever character you feed it and repeats it exactly 69 times. So if you give it 'A', you get a buffer of 69 'A's.

But here's where it gets spicy – look at that MD5 function call. It's not your standard MD5. It takes three parameters, and that second one? That's a custom initialization vector that gets updated after every character.

## The Chain Reaction

This is where I realized what I was really up against. The binary starts with a standard MD5 IV:

```
1032547698BADCFEEFCDAB8967452301h
```

Which is just the standard MD5 magic constants (`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`) arranged in little-endian format.

But after processing the first character, it takes the resulting hash and uses THAT as the IV for the second character. And so on. So you get:

 > Position 0: MD5("wwwww..." × 69, standard_IV) → hash0
> 
 > Position 1: MD5("second_char" × 69, hash0) → hash1
> 
 > Position 2: MD5("third_char" × 69, hash1) → hash2

Each position depends on getting every previous position exactly right. Screw up position 5, and positions 6 through 41 are all wrong no matter what.

## Confirming My Suspicions

I had a hunch that position 0 might be 'w' (call it intuition or lucky guessing), so I tested my theory by sending the same character to all 42 positions. Sure enough, each position spit out a completely different hash, but the pattern matched my expectations.

## Wrestling with the MD5 Beast

Now I had to figure out exactly how this custom MD5 worked. Looking at the disassembled `md5Sum__chal_u47` function, I could see all the hallmarks of a real MD5 implementation:

The four-round structure was there:
```c
if ( v32 > 15 )      // Rounds 2-4
if ( v32 > 31 )      // Rounds 3-4  
if ( v32 > 47 )      // Round 4
```

The auxiliary functions were correct:
```c
// F function: v26 ^ v31 & (v26 ^ v30)
// G function: v30 ^ v26 & (v30 ^ v31)  
// H function: v26 ^ v30 ^ v31
// I function: v30 ^ (v31 | ~v26)
```

Even the index calculations matched the MD5 spec perfectly:
```c
v33 = v32;                           // g = i
v33 = (5 * (_BYTE)v32 + 1) & 0xF;    // g = (5*i + 1) mod 16
v33 = (3 * (_BYTE)v32 + 5) & 0xF;    // g = (3*i + 5) mod 16
v33 = (7 * (_BYTE)v32) & 0xF;        // g = (7*i) mod 16
```

This was legit MD5, just with the ability to swap out the initialization vector.

## Crafting the Exploit

I knew I had to implement my own MD5 with custom IV support to match what the binary was doing. No way around it – I had to build the whole thing from scratch:

```python
class CustomMD5:
    def __init__(self, iv=None):
        if iv is None:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        else:
            # Custom IV replaces the standard constants
            if isinstance(iv, bytes) and len(iv) == 16:
                self.h = list(struct.unpack('<4I', iv))
            elif isinstance(iv, list) and len(iv) == 4:
                self.h = iv[:]
```

I implemented all 64 rounds, the proper bit rotations, the magic constants – everything. Then I built a solver that would brute force each position sequentially:

```python
def solve_position(target_hash, current_iv, charset=None):
    if charset is None:
        charset = string.ascii_letters + string.digits + "_{}-!@#$%^&*()+=[]{}|\\:;\"'<>,.?/~`"
    
    for char in charset:
        repeated_char = char * 69
        md5_hasher = CustomMD5(current_iv)
        md5_hasher.update(repeated_char)
        result_hash = md5_hasher.digest()
        
        if result_hash.hex() == target_hash:
            return char, result_hash
    
    return None, None
```

## The Target Hashes

I had to extract the target hashes from the binary. These were the values each position needed to produce:

```python
targets = [
    "a1ef290e2636bf553f39817628b6ca49",  # Position 0
    "ff7df97d4ab395232ff5a6c9f11c8ca1",  # Position 1
    "7fa595774eb5fee91502f8c5edd00eba",  # Position 2
    # ... and 39 more
]
```

## Cracking the Chain

With my custom MD5 implementation ready and the target hashes in hand, I started the sequential attack:

```python
current_iv = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
flag = ""

for i in range(len(targets)):
    char, hash_result = solve_position(targets[i], current_iv)
    if char is not None:
        flag += char
        current_iv = list(struct.unpack('<4I', hash_result))
    else:
        break
```

Position 0 came back as 'w' just like I suspected. Position 1 was 'w' again. Then 'f', then '{'. I was getting somewhere.

The solver chugged through all 42 positions, taking a few seconds per character as it brute forced through the possible character set. Each successful position gave me the hash I needed to unlock the next.

## The Moment of Truth

```python
import hashlib
import struct
import string

class CustomMD5:
    _S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    _K = [int(abs(2**32 * __import__('math').sin(i + 1))) for i in range(64)]
    
    def __init__(self, iv=None):
        if iv is None:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        else:
            if isinstance(iv, bytes) and len(iv) == 16:
                self.h = list(struct.unpack('<4I', iv))
            elif isinstance(iv, list) and len(iv) == 4:
                self.h = iv[:]
            else:
                raise ValueError("IV must be 16 bytes or list of 4 32-bit integers")
    
    def _left_rotate(self, value, amount):
        return ((value << amount) | (value >> (32 - amount))) & 0xffffffff
    
    def _md5_round(self, a, b, c, d, x, s, k):
        return (b + self._left_rotate((a + x + k) & 0xffffffff, s)) & 0xffffffff
    
    def _process_chunk(self, chunk):
        w = list(struct.unpack('<16I', chunk))
        a, b, c, d = self.h
        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            f = (f + a + self._K[i] + w[g]) & 0xffffffff
            a, b, c, d = d, (b + self._left_rotate(f, self._S[i])) & 0xffffffff, b, c
        self.h[0] = (self.h[0] + a) & 0xffffffff
        self.h[1] = (self.h[1] + b) & 0xffffffff
        self.h[2] = (self.h[2] + c) & 0xffffffff
        self.h[3] = (self.h[3] + d) & 0xffffffff
    
    def update(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        msg = data + b'\x80'
        while len(msg) % 64 != 56:
            msg += b'\x00'
        msg += struct.pack('<Q', len(data) * 8)
        for i in range(0, len(msg), 64):
            self._process_chunk(msg[i:i + 64])
    
    def digest(self):
        return struct.pack('<4I', *self.h)
    
    def hexdigest(self):
        return self.digest().hex()

def solve_position(target_hash, current_iv, charset=None):
    if charset is None:
        charset = string.ascii_letters + string.digits + "_{}-!@#$%^&*()+=[]{}|\\:;\"'<>,.?/~`"
    for char in charset:
        repeated_char = char * 69
        md5_hasher = CustomMD5(current_iv)
        md5_hasher.update(repeated_char)
        result_hash = md5_hasher.digest()
        result_hex = result_hash.hex()
        if result_hex == target_hash:
            return char, result_hash
    return None, None

def main():
    targets = [
        "a1ef290e2636bf553f39817628b6ca49",
        "ff7df97d4ab395232ff5a6c9f11c8ca1", 
        "7fa595774eb5fee91502f8c5edd00eba",
        "4176ef60c3a4b053b2db4a7dc693bbfe",
        "f19f7c2b248fdec315a0ed8bed62c31c",
        "24c02e87f82aa9e0586aa951a906626e",
        "003147a4a9a1f1bfa520b3219230d204",
        "9d49996864ad749ec2e273cd80d7fa5b",
        "5bdb359258139a8c6c3c6613a129ecea",
        "0827848a45b29ba90dd4714565798ecc",
        "aa186e7db388e6684e5608b1feac302e",
        "437ea83e7e9e0c6ecbc356946b9417ca",
        "9c29460733a9b02073968a21c4438596",
        "026cec522d0ac9b48d97f8ae887e7b3f",
        "1ff6a3f4946cb71d79db9d59d7745961",
        "3530df992b9e9dee09c97119838c49c2",
        "4e836177689d966b1285eed0da79e1b3",
        "2cf53ef0b8d134d39d11d40d45a1116e",
        "afc115a17f64e0a25445cbdd42b7cd9b",
        "83a32900ef6cba8bf15d01df92f35adf",
        "41d4cf133d1797d7c867001b3c7df6fe",
        "1c340576390b8a1cf8ea55e993089cc0",
        "d158a36c4edd158457f1ba2f7296bd76",
        "7b69d9576a510c60895d5052a7d0faf7",
        "3f60c20f46c97cf6b5f8593f9cef1caf",
        "8a10ed2389aaffc6c67b07a551d56c49",
        "f6663e53e17e1947bb8afa39088aa254",
        "6d96d7a28a58a845dce3030ca1dc4609",
        "d5f0b42666ed44c18c7d2338c862fcd2",
        "5119febc41fbd51578ee314e54841387",
        "ac200d1b6ce5ce96f040e7edf50f0293",
        "750b48a60b0af661bc1db534adb3d2eb",
        "6eddbf7cfdad9ad5153b2432743c358c",
        "a280c57e6f7708de619200f8e359d221",
        "99edd67a72637df4955d8ca640ff2321",
        "1949e4d4fd3c838b49dd84764e97f784",
        "3218deb8c50060b193f74894c6e3f5cd",
        "33bef1ea8c121f88ad1aeffeb83c345a",
        "a3ac5165f8fe7cca129d45f7c53fc88b",
        "67427db5da0e463f4946d7a199a5c185",
        "3fcdf9ba55298b59a503b31dd0ecf1cd",
        "0c5676da1b08700f848c8faf2bd4b8be"
    ]
    current_iv = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    flag = ""
    print("Starting MD5 chain solver...")
    print(f"Initial IV: {[hex(x) for x in current_iv]}")
    print("\nTesting position 0 with known 'w'...")
    repeated_w = 'w' * 69
    test_hasher = CustomMD5(current_iv)
    test_hasher.update(repeated_w)
    test_result = test_hasher.hexdigest()
    print(f"'w' * 69 with standard IV: {test_result}")
    print(f"Target for position 0:      {targets[0]}")
    print(f"Match: {test_result == targets[0]}")
    if test_result == targets[0]:
        print("✓ IV handling is correct!")
    else:
        print("✗ IV handling needs adjustment. Let's try different approaches...")
        iv_bytes = struct.pack('<4I', *current_iv)
        test_hasher2 = CustomMD5(iv_bytes)
        test_hasher2.update(repeated_w)
        test_result2 = test_hasher2.hexdigest()
        print(f"With IV as bytes: {test_result2}")
        standard_hash = hashlib.md5(repeated_w.encode()).hexdigest()
        print(f"Standard MD5: {standard_hash}")
        return
    for i in range(len(targets)):
        print(f"\nSolving position {i}...")
        char, hash_result = solve_position(targets[i], current_iv)
        if char is not None:
            print(f"✓ Position {i}: '{char}' -> {hash_result.hex()}")
            flag += char
            current_iv = list(struct.unpack('<4I', hash_result))
        else:
            print(f"✗ Position {i}: No solution found!")
            print(f"Current IV: {[hex(x) for x in current_iv]}")
            break
    print(f"\nFinal flag: {flag}")
    print(f"Length: {len(flag)}")

if __name__ == "__main__":
    main()
```

my solver spit out:

```
wwf{missile_launched_sucessfully_3a34f233}
```

42 characters exactly. I fed this back to the original binary and... success! No crash, no error message. The binary accepted the flag and completed successfully.


Let me know if you need further style tweaks or want to convert this for another markdown flavor!
