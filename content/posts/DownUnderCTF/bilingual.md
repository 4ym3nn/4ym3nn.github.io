+++
date = '2025-07-21T19:41:23+01:00'
draft = false
title = 'bilingual'
hideToc = false
+++

# DownUnderCTF 2025: rev/bilingual

![image](https://github.com/user-attachments/assets/59382842-e292-4ce3-883e-73180e9dbbed)

## Description

Two languages are better than one!

Regards,
FozzieBear (cybears)

## Solution

We are given this script:

```python
DATA = "eNrtfQt8k0XW96RNei8p0mBBxIDBFhAoTXUrpZp........."
import argparse, base64, ctypes, zlib, pathlib, sys
PASSWORD = "cheese"
FLAG = "jqsD0um75+TyJR3z0GbHwBQ+PLIdSJ+rojVscEL4IYkCOZ6+a5H1duhcq+Ub9Oa+ZWKuL703"
KEY = "68592cb91784620be98eca41f825260c"
HELPER = None

def decrypt_flag(password):
    A = "utf-8"
    flag = bytearray(base64.b64decode(FLAG))
    buffer = (ctypes.c_byte * len(flag)).from_buffer(flag)
    key = ctypes.create_string_buffer(password.encode(A))
    result = get_helper().Decrypt(key, len(key) - 1, buffer, len(buffer))
    return flag.decode(A)

def get_helper():
    global HELPER
    if HELPER:
        return HELPER
    data = globals().get("DATA")
    if data:
        dll_path = pathlib.Path(__file__).parent / "hello.bin"
        if not dll_path.is_file():
            with open(dll_path, "wb") as dll_file:
                dll_file.write(zlib.decompress(base64.b64decode(data)))
        HELPER = ctypes.cdll.LoadLibrary(dll_path)
    else:
        0
    return HELPER

def check_three(password):
    return check_ex(password, "Check3")

def check_four(password):
    return check_ex(password, "Check4")

def check_ex(password, func):
    GetIntCallbackFn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
    class CallbackTable(ctypes.Structure):
        _fields_ = [("E", GetIntCallbackFn)]
    @GetIntCallbackFn
    def eval_int(v):
        return int(eval(v))
    table = CallbackTable(E=eval_int)
    helper = get_helper()
    helper[func].argtypes = [ctypes.POINTER(CallbackTable)]
    helper[func].restype = ctypes.c_int
    return helper[func](ctypes.byref(table))

def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def callback(i):
        return ord(password[i - 3]) + 3
    return get_helper().Check2(callback)

def check_one(password):
    if len(password) != 12:
        return False
    return get_helper().Check1(password) != 0

def check_password(password):
    global PASSWORD
    PASSWORD = password
    checks = [check_one, check_two, check_three, check_four]
    result = True
    for check in checks:
        result = result and check(password)
    return result

def main():
    parser = argparse.ArgumentParser(description="CTF Challenge")
    parser.add_argument("password", help="Enter the password")
    args = parser.parse_args()
    if check_password(args.password):
        flag = decrypt_flag(args.password)
        print("Correct! The flag is DUCTF{%s}" % flag)
        return 0
    else:
        print("That is not correct")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

When running this on Linux, I encountered an error due to an invalid ELF header. This suggests that hello.bin is not a native Linux binary, but rather a Windows DLL or some other non-ELF format. The script attempts to load it using ctypes.cdll.LoadLibrary, which confirms it's expecting a shared library (DLL) to call functions . This behavior is evident in the get_helper function.


## The Role of get_helper in Library Loading

```python
def get_helper():
    global HELPER
    if HELPER:
        return HELPER
    data = globals().get("DATA")
    if data:
        dll_path = pathlib.Path(__file__).parent / "hello.bin"
        if not dll_path.is_file():
            with open(dll_path, "wb") as dll_file:
                dll_file.write(zlib.decompress(base64.b64decode(data)))
        HELPER = ctypes.cdll.LoadLibrary(dll_path)
    else:
        0
    return HELPER
```

This function performs three **main operations**:

### Dynamic Extraction
- Uses a global `HELPER` variable to ensure the library is only loaded once
- The binary library is embedded in the script as base64-encoded, zlib-compressed data in the `DATA` variable

### File Extraction
If `hello.bin` doesn't exist, it:
- Base64 decodes the `DATA` string
- Decompresses it using zlib
- Writes the binary data to `hello.bin`

### Library Loading
- Uses `ctypes.cdll.LoadLibrary()` to load the extracted binary as a shared library
- Returns the loaded library object for calling its functions

```python
def check_password(password):
    global PASSWORD
    PASSWORD = password
    checks = [check_one, check_two, check_three, check_four]
    result = True
    for check in checks:
        result = result and check(password)
    return result


def main():
    parser = argparse.ArgumentParser(description="CTF Challenge")
    parser.add_argument("password", help="Enter the password")
    args = parser.parse_args()
    if check_password(args.password):
        flag = decrypt_flag(args.password)
        print("Correct! The flag is DUCTF{%s}" % flag)
        return 0
    else:
        print("That is not correct")
        return 1
```

Once the library is loaded, the program begins validating the password through a series of checks check_one, check_two, check_three, and check_four starting with check_one.

Let's walk through each check step by step.

## Check1 :

```python
def check_one(password):
    if len(password) != 12:
        return False
    return get_helper().Check1(password) != 0
```

It checks the password length (must equal 12), then calls `Check1` from the loaded library from `hello.bin`. Let's examine it:

```c
int64_t Check1(char* arg1)
{
    char rdx = *(uint8_t*)arg1;
    int64_t result;
    result = (rdx ^ 0x43) == 0xb;
    data_180009000 = rdx | 0x72;
    return result;
}
```

It takes `char rdx = *(uint8_t*)arg1`, which interprets the first character of `arg1` (i.e., `arg1[0]`, which is `password[0]`) as an ASCII value and stores it in `rdx`. The function returns 1 (true) if `(rdx ^ 0x43) == 0x0b`, which implies `rdx == 0x0b ^ 0x43 = 0x48`, i.e., 'H'.

### Results

So, `password[0] = 'H'` (ASCII 0x48).

It also sets `data_180009000 = 0x48 | 0x72` to `data_180009000 = 0x7a`.

## Check2 :

```python
def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def callback(i):
        return ord(password[i - 3]) + 3
    return get_helper().Check2(callback)
```

```c
uint64_t Check2(int64_t arg1)
{
    int32_t rsi = 0;
    char rbp = arg1(8) ^ data_180009000;
    int32_t rbx;
    rbx = rbp == 9;
    rbp += arg1(9);
    
    if (rbp == 0x74)
        rsi = rbx;
    
    data_180009001 = ~(rbp + 0x1e);
    return (uint64_t)rsi;
}
```

### Explanation

The function `Check2` receives a callback (defined in Python) which returns `ord(password[i - 3]) + 3`. This means:
- `callback(8) → ord(password[5]) + 3`
- `callback(9) → ord(password[6]) + 3`

It computes:
`rbp = callback(8) ^ data_180009000`

Since `data_180009000 = 0x7a`, we want:
`(ord(password[5]) + 3) ^ 0x7a == 9`
`→ ord(password[5]) + 3 = 0x7a ^ 0x09 = 0x73`
`→ ord(password[5]) = 0x70`
`→ password[5] = 'p'`

Then it adds the result of `callback(9)`:
`rbp += ord(password[6]) + 3`

To satisfy the condition `rbp == 0x74`, we need:
`9 + ord(password[6]) + 3 = 0x74`
`→ ord(password[6]) = 0x68`
`→ password[6] = 'h'`

If both conditions are met:
- `rbp == 9` before the addition, and
- `rbp == 0x74` after the addition

Then `rsi` is set to 1, and the function returns 1.

Before returning, the function sets a global value:
`data_180009001 = ~(rbp + 0x1e)`

Since `rbp == 0x74`, this becomes:
`data_180009001 = ~0x92 = 0xFFFFFFFFFFFFFF6D`

But if `data_180009001` is a one-byte variable (e.g., char), only the least significant byte is stored:
`data_180009001 = 0x6D`  // ASCII 'm'

### Deduced Password Characters

To pass `check_two`, the password must satisfy:
- `password[5] = 'p'`
- `password[6] = 'h'`
- Side effect: `data_180009001` is set to `0x6D` ('m')

So what we have so far is:
- `data_180009001 = 0x6D`
- `data_180009000 = 0x7a`

```python
password[0] = 'H'
password[5] = 'p'
password[6] = 'h'
```

## Check3 :

```python
def check_three(password):
    return check_ex(password, "Check3")
```

To understand `check_three`, we need to understand `check_ex` first:

```python
def check_ex(password, func):
    GetIntCallbackFn = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)

    class CallbackTable(ctypes.Structure):
        _fields_ = [("E", GetIntCallbackFn)]

    @GetIntCallbackFn
    def eval_int(v):
        return int(eval(v))

    table = CallbackTable(E=eval_int)
    helper = get_helper()
    helper[func].argtypes = [ctypes.POINTER(CallbackTable)]
    helper[func].restype = ctypes.c_int
    return helper[func](ctypes.byref(table))
```

We notice three **main operations**:

**1. Creates Callback System**
- Defines a function pointer type that takes a string and returns an integer
- Creates a structure to hold this callback function

**2. Implements Evaluation Callback**
- `eval_int(v)` receives string expressions from the DLL
- Executes them as Python code using `eval()`
- Returns the result as an integer

**3. Calls DLL Function**
- Passes the callback structure to the specified DLL function
- The DLL can now send Python expressions back to be evaluated

Let's see how it's called in the shared library:

```c
int64_t check3(int64_t arg1) {
    char buffer1[0x6c8];
    int64_t cookie = __security_cookie ^ (int64_t)&buffer1;

    // Initial data block setup
    uint8_t data[16] = {0};
    *(uint32_t*)(data + 4) = 0x530053; // 'S\0S'
    *(uint16_t*)(data + 8) = 0x57;      // 'W'

    int i = 0;
    uint16_t* out = (uint16_t*)data;

    while (i < 8) {
        uint8_t result = 0;

        switch (i) {
            case 0:
                result = data[6] ^ 0x03;
                break;
            case 1:
                result = data[0] ^ 0x11;
                break;
            case 5:
                result = data[8] ^ 0x18;
                break;
            case 6:
                result = data[10] ^ 0x1D;
                break;
            case 7:
                result = data[12] ^ 0x16;
                break;
        }

        if (result)
            *out = (uint16_t)result;

        out++;
        i++;
    }

    // Prepare and parse input strings
    char format[24] = "ord(%s[%d])";
    char input[128] = {0};
    char output[24] = {0};

    uint16_t* resultData = (uint16_t*)output;
    int index = 0;

    while (index < 12) {
        snprintf(input, sizeof(input), format, (char*)data, index);
        resultData[index] = ((int (*)(char*))arg1)(input);
        index++;
    }

    // Collect specific characters from buffer
    char a = output[12];
    char b = output[14];
    char c = output[4];
    char d = output[6];

    // Prepare comparison format
    char cmp_buffer[1024] = {0};
    char extra[256] = {0};

    snprintf(cmp_buffer, sizeof(cmp_buffer), "%d + 2 == %d and %d == %d and (...)", b);

    for (int k = 0; k < 3; ++k) {
        snprintf(extra, sizeof(extra), " and %d > 48 and %d < 57", ((char*)&a)[k], ((char*)&a)[k]);
        strcat(cmp_buffer, extra);
    }

    int64_t result = ((int (*)(char*))arg1)(cmp_buffer);
    __security_check_cookie(cookie ^ (int64_t)&buffer1);
    return result;
}
```

It constructs something like:
```
"%d + 2 == %d and %d == %d and (%d > 48 and %d < 57) and %d > 48 and %d < 57"
```
and passes it to eval.

I dumped the `v` value and passed unique characters as input to find the constraints. The `v` was like:
```python
108 + 2 == 105 and 101 == 108 and (105 - b) == 105 and 101 > 48 and 101 < 57 and 108 > 48 and 108 < 57 and 105 > 48 and 105 < 57
```

So I mapped them to positions and got:
### Extracted Constraints

```python
password[8] + 2 == password[11]  
password[7] == password[8]       
password[11] - eval(password[4]) == password[11]
50<ord(password[11])<57
48<ord(password[7])<57
48<ord(password[8])<57
```

## Check4 :
### Overview    
```python
def check_four(password):
    return check_ex(password, "Check4")
```
Calls check_ex with "Check4" as the function name and sets up a callback system that allows the native Check4 function in the DLL to execute Python expressions.

The arg1 parameter passed to Check4 is a pointer to a callback table containing the function eval_int, defined as:
```python
def eval_int(v):
    return int(eval(v))
```
This means any time the native code calls (*arg1)(value), it triggers a call to eval_int(value), effectively executing eval(value) in Python. For example, in the disassembly:
```c
__builtin_wcscpy(dest: &var_270, src: u"ord(PASSWORD[1])")
...
char rax_2 = (*arg1)(&var_270)
```
The string "ord(PASSWORD[1])" is passed to the callback, resulting in a call to eval("ord(PASSWORD[1])"), which returns the corresponding integer to the native code.

Let's look at the `check4` function:

here is the full function [Check4.c](https://github.com/4ym3nn/4ym3nn.github.io/blob/main/content/posts/DownUnderCTF/originalCheck4.c)

after variables setup 
```c
if (j_sub_180002060(&var_298, 0x1a, &s, &data_180009000, 2, var_2a0) == 0)
    result = 0
```

We can see that `j_sub_180002060` is called three times. What is it?
```c
int64_t sub_180002060(int64_t arg1, int64_t arg2, char* arg3, int64_t arg4, int32_t arg5, int32_t arg6)
    memcpy(dest: arg3, src: arg1, count: arg2.d)
    j_sub_1800013f0(arg4, arg5, arg3, arg2.d) // this function jumps to  sub_1800013f0 function
    int32_t result
    result.b = j_sub_180001630(arg3, arg2 u>> 1) == arg6
    return result
```

It calls two functions:

1- [`sub_1800013f0`](https://github.com/4ym3nn/4ym3nn.github.io/blob/main/content/posts/DownUnderCTF/RC4.c) , which is a SIMD-optimized implementation of the RC4 encryption/decryption algorithm.

I cleaned and simplified it into a standard C version:

```c
void rc4(uint8_t *key, int keylen, uint8_t *data, int len) {
    uint8_t s[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) s[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    i = j = 0;
    for (int x = 0; x < len; x++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[x] ^= s[(s[i] + s[j]) % 256];
    }
}
```
2- The second call is a hash check:
```c
int32_t result = (sub_180001630(arg3, arg2 >> 1) == arg6);
```
Which corresponds to the following logic:
```c
 result.b = hash_utf16_string(dataa, dataLength u>> 1) == expected_hash;
```

And here is the cleaned hash implementation:

```c
uint32_t hash_function(uint8_t *data, int len) {
    uint32_t result = 0x1505;
    for (int i = 0; i < len; i++) {
        result = (result * 0x21) ^ data[i];
    }
    return result;
}

uint32_t hash_utf16_string(uint8_t *data, int len) {
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        if (data[i] == 0 && data[i + 1] == 0)
            break;
    }
    return hash_function(data, i);
}

```
This is essentially a DJB2 Hash Function adapted for UTF-16 encoded input, used for hash verification after decryption.

Putting it all together, the original function j_sub_180002060 can be understood and renamed as: `DecryptRC4andCheckHash` 

```c
int64_t DecryptRC4andCheckHash(int64_t data, int64_t dataLength, char* dataa, int64_t key, int32_t keyLength, int32_t expected_hash)
{
    memcpy(dest: dataa, src: data, count: dataLength.d);
    rc4(key, keyLength, dataa, dataLength.d);
    int32_t result;
    result.b = hash_utf16_string(dataa, dataLength u>> 1) == expected_hash;
    return result;
}
```
Which is essentially:
```c
void rc4(uint8_t *key, int keylen, uint8_t *data, int len) {
    uint8_t s[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) s[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    i = j = 0;
    for (int x = 0; x < len; x++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[x] ^= s[(s[i] + s[j]) % 256];
    }
}

uint32_t hash_function(uint8_t *data, int len) {
    uint32_t result = 0x1505;
    for (int i = 0; i < len; i++) {
        result = (result * 0x21) ^ data[i];
    }
    return result;
}

uint32_t hash_utf16_string(uint8_t *data, int len) {
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        if (data[i] == 0 && data[i + 1] == 0)
            break;
    }
    return hash_function(data, i);
}

memcpy(data, ciphertext, DATA_LEN);
rc4(key, 8, data, DATA_LEN);

uint32_t h = hash_utf16_string(data, DATA_LEN);
if (h == EXPECTED_HASH) {
    return 1;
} else {
    return 0;
}
```
This function simply:

    Copies the encrypted data into a buffer.

    Decrypts it using RC4 with a given key.

    Computes a hash of the decrypted data and compares it to a known hash.

The function `DecryptRC4AndCheckHash` is invoked three times, and in each call, it performs a stage of decryption.

To proceed through each stage successfully, we must recover the following for each:

    key – the decryption key

    key_length – the length of the key

    enc_data – the encrypted data buffer

    length_enc_data – the length of the encrypted data

Each stage uses this data in a DecryptRC4andCheckHash(...) call to:

    Decrypt the data using RC4,

    And verify it using a DJB2-based hash function.

If the hash check passes, additional logic is executed .
Otherwise, the function exits early.

So, in summary:

we must extract or reverse the correct **(key, key_length, enc_data, length_enc_data)** tuple for all three stages to reach the function’s final logic.

### Stage One

```c
  __builtin_wcscpy(dest: &var_270, src: u"ord(PASSWORD[1])");
  __builtin_wcscpy(dest: &var_248, src: u"ord(PASSWORD[2])");
  __builtin_wcscpy(dest: &var_220, src: u"ord(PASSWORD[3])");

  char ord1 = (*arg1)(&var_270);
  char ord2 = (*arg1)(&var_248);
  char ord3 = (*arg1)(&var_220);
```
In this stage, the function prepares the values needed for decryption:

    It loads a hardcoded 26-byte encrypted buffer (enc_data) into var_298.

    It sets the key pointer to &data_180009000 and key length to 2.

    It initializes an empty buffer s to receive the decrypted output.

    It sets the hash constant to 0x6293def8.

```c
if (_DecryptRC4andCheckHash(&var_298, 0x1a, &s, &data_180009000, 2, 0x6293def8) == 0)
```

We know the parameters:

    Key: 2 bytes from data_180009000
    → key = { 0x6d, 0x7a }

    Encrypted data: 26 bytes stored in var_298

    Expected hash: 0x6293def8
Here’s the equivalent C implementation:

```c
int main() {
    uint8_t ciphertext[DATA_LEN] = {
        0xf2, 0x1e, 0x2a, 0xf4, 0x21, 0xef, 0xf7, 0x29, 0x1b, 0x8b,
        0x96, 0x17, 0x78, 0x8b, 0x32, 0x90, 0x87, 0xb4, 0x58, 0xb5,
        0xe1, 0xed, 0xb9, 0x48, 0x3e, 0xd9
    };

    uint8_t key[2] = {0x6d, 0x7a};
    uint8_t data[DATA_LEN];
    memcpy(data, ciphertext, DATA_LEN);
    rc4(key, 2, data, DATA_LEN);
    uint32_t h = hash_utf16_string(data, DATA_LEN);
    if (h == 0x6293def8) {
        printf("[+] Decrypted data: ");
        for (int i = 0; i < DATA_LEN; i++) putchar(data[i]);
        printf("\n");
        return 0;
    }
    return 1;
}
```
The decrypted data is interpreted as int(KEY[0:4]) — i.e., first 4 bytes as a little-endian integer.

### Stage Two
If the check passes from stage one , it evaluates a function pointer arg1 with `int(KEY[0:4])`:
```c
    int32_t rax_3 = (*arg1)(&ord9);  // eval(int(KEY[0:4]))
    data_180009004 = ord1;
    data_180009005 = ord2;
```
Then it prepares decryption-related values:
```c
    var_298 = 0x5ac1e9d0;
    data_180009003 = (rax_3 >> 3) ^ 0x36;
    data_180009006 = ord3 ^ ord1 ^ ord2 ^ 0x10;
```

Static values written to the stack:
```c
    int32_t var_294_1 = 0x31280c9e;
    __builtin_strncpy(&var_290, "X$]h", 4);
    __builtin_memcpy(&var_28c, 
    "\x54\x8d\x6f\xe7\xf6\xdb\xd7\xe5\xc0\x4b\x28\x46"
    "\xe7\xa4\x7e\xcd\x07\xf8\xf4\x41", 0x14);
```

The variable var_f8 is cleared with a memset, and then passed as the output buffer for decryption:
```c
    memset(&var_f8, 0, 0xc0);  // clear buffer
    if (_DecryptRC4andCheckHash(&var_298, 0x20, &var_f8, &data_180009000, 8, 0x69fa99d) == 0)
```
But from the **disassembly**, we realize the actual ciphertext is stored directly on the stack, starting at rsp+0x30, not in var_28c. The full encrypted payload is loaded as follows:
```assembly
mov dword [rsp+0x30], 0x5ac1e9d0
mov dword [rsp+0x34], 0x31280c9e
mov dword [rsp+0x38], 0x685d2458
mov dword [rsp+0x3c], 0xe76f8d54
mov dword [rsp+0x40], 0xe5d7dbf6
mov dword [rsp+0x44], 0x46284bc0
mov dword [rsp+0x48], 0xcd7ea4e7
mov dword [rsp+0x4c], 0x41f4f807
```
Putting it all together, the encryped_data is:
```c
uint8_t ciphertext[32] = {
    0xd0, 0xe9, 0xc1, 0x5a,
    0x9e, 0x0c, 0x28, 0x31,
    0x58, 0x24, 0x5d, 0x68,
    0x54, 0x8d, 0x6f, 0xe7,
    0xf6, 0xdb, 0xd7, 0xe5,
    0xc0, 0x4b, 0x28, 0x46,
    0xe7, 0xa4, 0x7e, 0xcd,
    0x07, 0xf8, 0xf4, 0x41
};
```

Key length is 8, and the key:
```c
data_180009000 = 0x7a
data_180009001 = 0x6d
data_180009002 = 0xcc
data_180009003 = (key0to4 >> 3) ^ 0x36   
data_180009004 = ord1
data_180009005 = ord2
data_180009006 = ord3 ^ ord1 ^ ord2 ^ 0x10
data_180009007 = 0xcc
```

After brute forcing ord1,ord2,ord3, I got:
```c
uint8_t key[8] = { 0x7a, 0x6d, 0xcc, 0x6f, 0x79, 0x64, 0x7f, 0xcc };
```

So we know:
```python
password[0] = 0x48  # 'H'
password[1] = 0x79  # 'y'
password[2] = 0x64  # 'd'
password[3] = 0x7f ^ 0x64 ^ 0x79 ^ 0x10 = 0x72  # 'r'
password[4] = '0'
password[5] = 'p'
password[6] = 'h'
password[7] = password[11] - 2  # and in range '1'...'9'
password[8] = password[7]
password[9] = unknown
password[10] = unknown
password[11] = in range '3' to '9'
```

We could brute force the two bytes at index 9,10 and get the flag, but I wanted to complete the challenge.

### Stage Three

In the same way, I extracted the encrypted data:
```c
ciphertext[DATA_LEN] = {
    0xd6,0xe9,0xdd,0x5a,0x8e,0x0c,0x28,0x31,0x43,0x24,0x59,0x68,0x5e,0x8d,
    0x67,0xe7,0x91,0xdb,0xa2,0xe5,0xa0,0x4b,0x31,0x46,0x90,0xa4,0x67,0xcd,
    0x6b,0xf8,0xeb,0x41,0x20,0x94
};
```

Using the same key:
```c
uint8_t key[8] = { 0x7a, 0x6d, 0xcc, 0x6f, 0x79, 0x64, 0x7f, 0xcc };
```

This decrypted to `int(key[0:2])`.

In this part, I dumped the last eval and saw `ord(PASSWORD[10])` instead of `ord(PASSWORD[9])`.

```c
result_1 = (uint32_t)orddd9 == (*(uint64_t*)arg1)(&key02) - 7;
```

So finally `ord(PASSWORD[10]) == eval(int(KEY[0:2], 16)) - 7` is `ord(PASSWORD[10]) = 97` ('a').
### Deduced Password Characters
```python
password[0]  = 0x48;  // 'H'
password[1]  = 0x79;  // 'y'
password[2]  = 0x64;  // 'd'
password[3]  = 0x7f ^ 0x64 ^ 0x79 ^ 0x10;  // = 0x72 → 'r'
password[4]  = 0x30;  // '0'
password[5]  = 0x70;  // 'p'
password[6]  = 0x68;  // 'h'
password[7]  = password[11] - 2;  // '1' to '7'
password[8]  = password[7];       // same as password[7]
password[9]  = 0x6e;  // 'n'
password[10] = 0x61;  // 'a'
password[11] = 0x32 to 0x39;  // '2' to '9'
```

And the cleaned version of the Check4 function is:

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

void rc4(uint8_t *key, int keylen, uint8_t *data, int len) {
    uint8_t s[256];
    int i, j = 0;
    for (i = 0; i < 256; i++) s[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
    }
    i = j = 0;
    for (int x = 0; x < len; x++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        uint8_t tmp = s[i]; s[i] = s[j]; s[j] = tmp;
        data[x] ^= s[(s[i] + s[j]) % 256];
    }
}

uint32_t hash_function(uint8_t *data, int len) {
    uint32_t result = 0x1505;
    for (int i = 0; i < len; i++) {
        result = (result * 0x21) ^ data[i];
    }
    return result;
}

uint32_t hash_utf16_string(uint8_t *data, int len) {
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        if (data[i] == 0 && data[i + 1] == 0)
            break;
    }
    return hash_function(data, i);
}

int RC4decryptCheckHash(uint8_t *enc_data, int enc_len, uint8_t *key, uint8_t *data_base, int key_len, uint32_t expected_hash) {
    uint8_t decrypted[256];
    memcpy(decrypted, enc_data, enc_len);
    
    uint8_t rc4_key[256];
    memcpy(rc4_key, key, key_len);
    for (int i = 0; i < key_len && i < 8; i++) {
        rc4_key[i + key_len] = data_base[i];
    }
    
    rc4(rc4_key, key_len + 8, decrypted, enc_len);
    
    uint32_t h = hash_utf16_string(decrypted, enc_len);
    if (h == expected_hash) {
        return 1;
    }
    return 0;
}

uint64_t Check4(int64_t arg1) {
    uint8_t data_180009000 = 0x7a;
    uint8_t data_180009001 = 0x6d;
    uint8_t data_180009002 = 0xcc;
    uint8_t data_180009003;
    uint8_t data_180009004;
    uint8_t data_180009005;
    uint8_t data_180009006;
    uint8_t data_180009007 = 0xcc;
    
    uint8_t data_base[8] = {data_180009000, data_180009001, data_180009002, data_180009003, 
                           data_180009004, data_180009005, data_180009006, data_180009007};
    
    char ord1 = (*(uint64_t*)arg1)("ord(PASSWORD[1])");
    char ord2 = (*(uint64_t*)arg1)("ord(PASSWORD[2])");
    char ord3 = (*(uint64_t*)arg1)("ord(PASSWORD[3])");
    
    uint32_t expected_hash1 = 0x6293def8;
    uint8_t enc_data1[] = {0xf2, 0x1e, 0x2a, 0xf4, 0x21, 0xef, 0xf7, 0x29, 0x1b, 0x8b,
                          0x96, 0x17, 0x78, 0x8b, 0x32, 0x90, 0x87, 0xb4, 0x58, 0xb5,
                          0xe1, 0xed, 0xb9, 0x48, 0x3e, 0xd9, 0x1a};
    
    uint8_t key0to4int[30];
    memset(key0to4int, 0, 30);
    
    if (!RC4decryptCheckHash(enc_data1, 0x1a, key0to4int, data_base, 2, expected_hash1)) {
        return 0;
    }
    
    int32_t key0to4 = (*(uint64_t*)arg1)(key0to4int);
    data_180009004 = ord1;
    data_180009005 = ord2;
    data_180009003 = (int8_t)(key0to4 >> 3) ^ 0x36;
    data_180009006 = ord3 ^ ord1 ^ ord2 ^ 0x10;
    
    uint8_t enc_data2[] = {0xd0,0xe9,0xc1,0x5a,0x9e,0x0c,0x28,0x31,0x58,0x24,0x5d,0x68,0x54,0x8d,0x6f,0xe7,
                          0xf6,0xdb,0xd7,0xe5,0xc0,0x4b,0x28,0x46,0xe7,0xa4,0x7e,0xcd,0x07,0xf8,0xf4,0x41};
    
    uint8_t ord9[192];
    memset(ord9, 0, 192);
    
    if (!RC4decryptCheckHash(enc_data2, 0x20, ord9, data_base, 8, 0x69fa99d)) {
        return 0;
    }
    
    int16_t ordd9 = (*(uint64_t*)arg1)(ord9);
    
    if (((key0to4 & 0x64) ^ (uint32_t)ordd9) != (*(uint64_t*)arg1)("int(KEY[11:13])")) {
        return 0;
    }
    
    int16_t ord10 = (*(uint64_t*)arg1)(ord9);
    
    uint32_t var_2a0_1 = 0xa7d53695;
    uint8_t enc_data3[] = {0xd6,0xe9,0xdd,0x5a,0x8e,0x0c,0x28,0x31,0x43,0x24,0x59,0x68,0x5e,0x8d,0x67,0xe7,
                          0x91,0xdb,0xa2,0xe5,0xa0,0x4b,0x31,0x46,0x90,0xa4,0x67,0xcd,0x6b,0xf8,0xeb,0x41,0x20,0x94};
    
    uint8_t key02[128];
    memset(key02, 0, 128);
    
    if (!RC4decryptCheckHash(enc_data3, 0x22, key02, data_base, 8, var_2a0_1)) {
        return 0;
    }
    
    int32_t result = (uint32_t)ord10 == (*(uint64_t*)arg1)("int(KEY[0:2],16)") - 7;
    return (uint64_t)result;
}
```
We have 7 possible passwords now:
```
Hydr0ph00na2
Hydr0ph11na3
Hydr0ph22na4
Hydr0ph33na5
Hydr0ph44na6
Hydr0ph55na7
Hydr0ph66na8
Hydr0ph77na9
```

And `Hydr0ph11na3` was the correct one:

```bash
PS E:\projects\bilingual> python new.py Hydr0ph11na3
Correct! The flag is DUCTF{the_problem_with_dynamic_languages_is_you_cant_c_types}
PS E:\projects\bilingual>
```
