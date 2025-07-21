+++
date = '2025-06-19T19:41:23+01:00'
draft = true
title = 'bilingual'
hideToc = false
+++
# DownUnderCTF2025 :
# rev/bilingual
<img width="1159" height="733" alt="image" src="https://github.com/user-attachments/assets/d8c92777-2bf7-46e8-b897-b9142a57f601" />


# Description

Two languages are better than one!

Regards,
FozzieBear (cybears)

# Solution
we are given this script
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
what i noticed when running this in linux i get that cannot run this in linux (non elf ) so i understand it is loading  DLL libary to interact with via python and this was clear in `get_help`
## `get_helper` function:
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
this function is doing three main things :

### Dynamic Extraction:
it Uses a global HELPER variable to ensure the library is only loaded once also The binary library is embedded in the script as base64-encoded , zlib-compressed data in the DATA variable 
then we go to 
### File Extraction: 
If hello.bin doesn't exist, it:
Base64 decodes the DATA string
Decompresses it using zlib
Writes the binary data to hello.bin
### Library Loading:
Uses ctypes.cdll.LoadLibrary() to load the extracted binary as a shared library
### Return:
Returns the loaded library object for calling its functions

## `check_one` function:
```python
def check_one(password):
    if len(password) != 12:
        return False
    return get_helper().Check1(password) != 0
```
it checks the password length if it is equal to 12 then it calls Check1 from the loaded library from `hello.bin` so let us take a look at it 
```c
18000115e    int64_t Check1(char* arg1)
1800016f0    {
1800016f0        char rdx = *(uint8_t*)arg1;
1800016fe        int64_t result;
1800016fe        result = (rdx ^ 0x43) == 0xb;
180001704        data_180009000 = rdx | 0x72;
18000170a        return result;
1800016f0    }
```

It takes char `rdx = *(uint8_t*)arg1;`, which interprets the first character of arg1 (i.e., `arg1[0]`, which is  `password[0]`) as an ASCII value and stores it in `rdx`. The function returns 1 (true) if `(rdx ^ 0x43) == 0x0b`, which implies `rdx == 0x0b ^ 0x43 = 0x48`, i.e., 'H'.
So,` password[0] = 'H' ` (ASCII 0x48) .
it also sets  `data_180009000== 0x48 | 0x72` to `data_180009000=0x7a`
## `check_two` function:
```python
def check_two(password):
    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)
    def callback(i):
        return ord(password[i - 3]) + 3
    return get_helper().Check2(callback)
```
```c
1800011b3    uint64_t Check2(int64_t arg1)
180001720    {
180001720        int32_t rsi = 0;
180001742        char rbp = arg1(8) ^ data_180009000;
180001754        int32_t rbx;
180001754        rbx = rbp == 9;
180001759        rbp += arg1(9);
180001759        
180001760        if (rbp == 0x74)
180001760            rsi = rbx;
180001760        
180001776        data_180009001 = ~(rbp + 0x1e);
180001787        return (uint64_t)rsi;
180001720    }
```
### Explanation:
The function Check2 receives a callback (defined in Python) which returns ord(password[i - 3]) + 3. This means:

    callback(8) → ord(password[5]) + 3

    callback(9) → ord(password[6]) + 3

    It computes:

rbp = callback(8) ^ data_180009000

Since data_180009000 = 0x7a, we want:

(ord(password[5]) + 3) ^ 0x7a == 9
→ ord(password[5]) + 3 = 0x7a ^ 0x09 = 0x73
→ ord(password[5]) = 0x70
→ password[5] = 'p'

Then it adds the result of callback(9):

rbp += ord(password[6]) + 3

To satisfy the condition rbp == 0x74, we need:

9 + ord(password[6]) + 3 = 0x74
→ ord(password[6]) = 0x68
→ password[6] = 'h'

If both conditions are met:

    rbp == 9 before the addition, and

    rbp == 0x74 after the addition,

Then rsi is set to 1, and the function returns 1.

Before returning, the function sets a global value:

data_180009001 = ~(rbp + 0x1e)

Since rbp == 0x74, this becomes:

data_180009001 = ~0x92 = 0xFFFFFFFFFFFFFF6D

But if data_180009001 is a one-byte variable (e.g., char), only the least significant byte is stored:

    data_180009001 = 0x6D  // ASCII 'm'

Final result:
To pass check_two, the password must satisfy:

    password[5] = 'p'

    password[6] = 'h'

    Side effect: data_180009001 is set to 0x6D ('m')
so what we have so far is 
`data_180009001 = 0x6D ` and `data_180009000 = 0x7a `
```python
password[0]='H'
password[5] = 'p'
password[6] = 'h'
```

## `check_three` function:
```python
def check_three(password):
    return check_ex(password, "Check3")
```
in order to understand the `check_three` we have to understand `check_ex` before :
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
we notice three main things :
**1. Creates Callback System**

Defines a function pointer type that takes a string and returns an integer
Creates a structure to hold this callback function

**2. Implements Evaluation Callback**

eval_int(v) receives string expressions from the DLL
Executes them as Python code using eval()
Returns the result as an integer

**3. Calls DLL Function**
Passes the callback structure to the specified DLL function 
The DLL can now send Python expressions back to be evaluated

let us see now how it is called in the shared library 
```c
1800017b0    int64_t Check3(int64_t arg1)
1800017b0    {
1800017b0        void var_6c8;
1800017de        int64_t rax_1 = __security_cookie ^ &var_6c8;
1800017e8        int512_t zmm0;
1800017e8        zmm0 = {0};
1800017eb        int128_t var_658;
1800017eb        int128_t* r8 = &var_658;
1800017f0        var_658 = {0};
1800017fa        *(uint32_t*)((char*)var_658)[4] = 0x530053;
180001802        int64_t i_2 = 0;
180001805        *(uint16_t*)((char*)var_658)[8] = 0x57;
18000180d        int32_t i = 0;
180001810        int128_t var_648 = {0};
180001810        
18000186d        do
18000186d        {
180001818            char rax_2;
180001818            
180001818            if (!i)
180001818            {
180001857                rax_2 = *(uint8_t*)((char*)var_658)[6] ^ 3;
180001859                label_180001859:
180001859                
18000185b                if (rax_2)
180001860                    *(uint16_t*)r8 = (int16_t)rax_2;
180001818            }
180001818            else
180001818            {
18000181d                if (i == 1)
18000181d                {
18000184e                    rax_2 = var_658 ^ 0x11;
180001850                    goto label_180001859;
18000181d                }
18000181d                
180001822                if (i == 5)
180001822                {
180001845                    rax_2 = *(uint8_t*)((char*)var_658)[8] ^ 0x18;
180001847                    goto label_180001859;
180001822                }
180001822                
180001827                if (i == 6)
180001827                {
18000183c                    rax_2 = *(uint8_t*)((char*)var_658)[0xa] ^ 0x1d;
18000183e                    goto label_180001859;
180001827                }
180001827                
18000182c                if (i == 7)
18000182c                {
180001833                    rax_2 = *(uint8_t*)((char*)var_658)[0xc] ^ 0x16;
180001835                    goto label_180001859;
18000182c                }
180001818            }
180001864            i += 1;
180001866            r8 += 2;
18000186d        } while (i < 8);
18000186d        
18000186f        zmm0 = {0};
180001872        void var_638;
180001872        void* rdi = &var_638;
180001876        int120_t var_636 = (int15_t){0};
18000187a        int32_t i_1 = 0;
18000187d        int40_t var_626 = (int5_t){0};
18000187d        
180001901        do
180001901        {
180001881            zmm0 = {0};
180001884            int32_t var_670;
180001884            __builtin_memcpy(&var_670, "ord(%s[%d])", 0x18);
1800018bd            int128_t s;
1800018bd            __builtin_memset(&s, 0, 0x80);
1800018e8            j_sscanf_s(&s, &var_670, &var_658);
1800018f5            i_1 += 1;
1800018f7            *(uint16_t*)rdi = (*(uint64_t*)arg1)(&s);
1800018fa            rdi += 2;
180001901        } while (i_1 < 0xc);
180001901        
180001907        uint32_t r14 = (uint32_t)*(uint8_t*)((char*)var_636)[0xc];
180001913        uint32_t rsi = (uint32_t)*(uint8_t*)((char*)var_636)[0xe];
180001919        uint32_t rbx = (uint32_t)*(uint8_t*)((char*)var_626)[4];
180001923        uint32_t rdi_1 = (uint32_t)*(uint8_t*)((char*)var_636)[6];
180001927        char var_678 = r14;
18000192c        char var_677 = rsi;
180001931        char var_676 = rbx;
180001935        char var_675 = rdi_1;
18000193a        void var_438;
18000193a        memset(&var_438, 0, 0x400);
18000194e        void var_538;
18000194e        memset(&var_538, 0, 0x100);
180001953        uint32_t var_688 = rbx;
18000195e        uint32_t var_690 = rdi_1;
180001969        uint32_t var_698 = rbx;
180001970        uint32_t var_6a0 = rsi;
180001977        uint32_t var_6a8 = r14;
18000197c        j_sscanf_s(&var_438, u"%d + 2 == %d and %d == %d and (%…", (uint64_t)rsi);
18000197c        
1800019f9        do
1800019f9        {
1800019a7            j_sscanf_s(&var_538, u" and %d > 48 and %d < 57", (uint64_t)(&var_678)[i_2]);
1800019b3            void var_43a;
1800019b3            void* rax_5 = &var_43a;
1800019c9            bool cond:0_1;
1800019c9            
1800019c9            do
1800019c9            {
1800019c0                cond:0_1 = *(uint16_t*)((char*)rax_5 + 2);
1800019c5                rax_5 += 2;
1800019c9            } while (cond:0_1);
1800019d2            int64_t rdx_1 = 0;
1800019f0            int16_t j;
1800019f0            
1800019f0            do
1800019f0            {
1800019e0                j = *(uint16_t*)(&var_538 + (rdx_1 << 1));
1800019e5                *(uint16_t*)((char*)rax_5 + (rdx_1 << 1)) = j;
1800019e9                rdx_1 += 1;
1800019f0            } while (j);
1800019f2            i_2 += 1;
1800019f9        } while (i_2 < 3);
1800019f9        
180001a02        int64_t result = (*(uint64_t*)arg1)(&var_438);
180001a10        j___security_check_cookie(rax_1 ^ &var_6c8);
180001a35        return result;
1800017b0    }
```
it is doing something like ```"%d + 2 == %d and %d == %d and (%d > 48 and %d < 57) and %d > 48 and %d < 57"``` and passes it to eval
so it is a little bit long so i just dumped  the `v` value and passes unique chars as input to find the constrains  which is passed to the eval to see the 
```python
    def eval_int(v):
        return int(eval(v))
```
the `v` was like that 
```python
108 + 2 == 105 and 101 == 108 and (105 - b) == 105 and 101 > 48 and 101 < 57 and 108 > 48 and 108 < 57 and 105 > 48 and 105 < 57
```
so i did map them to positions and get this 
```python
password[8] + 2 == password[11]  
password[7] == password[8]       
password[11] - eval(password[4]) == password[11]
```


