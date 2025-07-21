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

### `check_three` function :
```python
def check_four(password):
    return check_ex(password, "Check4")
```
Calls check_ex with "Check4" as the function name
Sets up callback system allowing Check4 DLL function to execute Python expressions
let us look through the check4 function 
```180001ae0    uint64_t Mod1::findC13Lines(
180001ae0      int64_t arg1)

180001b0e        void var_2c8
180001b0e        int64_t rax_1 = __security_cookie ^ &var_2c8
180001b1b        int32_t var_270
180001b1b        __builtin_wcscpy(dest: &var_270, src: u"ord(PASSWORD[1])")
180001b6f        int32_t var_248
180001b6f        __builtin_wcscpy(dest: &var_248, src: u"ord(PASSWORD[2])")
180001bac        int32_t var_220
180001bac        __builtin_wcscpy(dest: &var_220, src: u"ord(PASSWORD[3])")
180001be9        char rax_2 = (*arg1)(&var_270)
180001bf2        char rax_3 = (*arg1)(&var_248)
180001bfb        char rax_4 = (*arg1)(&var_220)
180001c00        int32_t var_2a0 = 0x6293def8
180001c0f        int32_t var_298
180001c0f        __builtin_memcpy(dest: &var_298, src: "\xf2\x1e\x2a\xf4\x21\xef\xf7\x29\x1b\x8b\x96\x17\x78\x8b\x32\x90\x87\xb4\x58\xb5\xe1\xed\xb9\x48\x3e\xd9", n: 0x1a)
180001c3d        int128_t s
180001c3d        __builtin_memset(&s, c: 0, n: 0x1e)
180001c57        int128_t s_1
180001c57        __builtin_memset(s: &s_1, c: 0, n: 0x60)
180001c86        uint64_t result
180001c86        
180001c86        if (j_sub_180002060(&var_298, 0x1a, &s, &data_180009000, 2, var_2a0) == 0)
180001e83            result = 0
180001c86        else
180001c90            int32_t rax_6 = (*arg1)(&s)
180001c95            data_180009004 = rax_2
180001c9e            data_180009005 = rax_3
180001cae            var_298 = 0x5ac1e9d0
180001cb6            data_180009003 = (rax_6 s>> 3).b ^ 0x36
180001cc6            data_180009006 = rax_4 ^ rax_2 ^ rax_3 ^ 0x10
180001cce            int32_t var_294_1 = 0x31280c9e
180001cdc            int32_t var_290
180001cdc            __builtin_strncpy(dest: &var_290, src: "X$]h", n: 4)
180001ce6            int32_t var_28c
180001ce6            __builtin_memcpy(dest: &var_28c, src: "\x54\x8d\x6f\xe7\xf6\xdb\xd7\xe5\xc0\x4b\x28\x46\xe7\xa4\x7e\xcd\x07\xf8\xf4\x41", n: 0x14)
180001d0e            void var_f8
180001d0e            memset(dest: &var_f8, c: 0, count: 0xc0)
180001d0e            
180001d43            if (j_sub_180002060(&var_298, 0x20, &var_f8, &data_180009000, 8, 0x69fa99d) == 0)
180001e83                result = 0
180001d43            else
180001d50                int16_t rax_8 = (*arg1)(&var_f8)
180001d5e                int112_t var_1e8
180001d5e                __builtin_wcscpy(dest: &var_1e8, src: u"11:13")
180001d5e                
180001d7d                if (((rax_6 & 0x64) ^ zx.d(rax_8)) != (*arg1)(&s))
180001e83                    result = 0
180001d7d                else
180001d99                    int16_t var_de
180001d99                    int16_t var_de_1 = var_de - 8
180001da3                    int16_t var_dc_1 = var_de - 9
180001dae                    int16_t var_da_1 = var_1e8:0xa.w
180001db9                    int16_t var_d8_1 = var_1e8:0xc.w
180001dc0                    int16_t rax_13 = (*arg1)(&var_f8)
180001dc5                    int32_t var_2a0_2 = 0xa7d53695
180001dd4                    var_298 = 0x5adde9d6
180001de0                    int32_t var_294_2 = 0x31280c8e
180001ded                    int32_t var_290_1
180001ded                    __builtin_strncpy(dest: &var_290_1, src: "C$Yh", n: 4)
180001dfa                    int32_t var_28c_1
180001dfa                    __builtin_memcpy(dest: &var_28c_1, src: "\x5e\x8d\x67\xe7\x91\xdb\xa2\xe5\xa0\x4b\x31\x46\x90\xa4\x67\xcd\x6b\xf8\xeb\x41\x20\x94", n: 0x16)
180001e02                    int128_t s_2
180001e02                    __builtin_memset(s: &s_2, c: 0, n: 0x80)
180001e02                    
180001e6a                    if (j_sub_180002060(&var_298, 0x22, &s_2, &data_180009000, 8, var_2a0_2) == 0)
180001e83                        result = 0
180001e6a                    else
180001e7a                        int32_t result_1
180001e7a                        result_1.b = zx.d(rax_13) == (*arg1)(&s_2) - 7
180001e7e                        result = zx.q(result_1)
180001e7e        
180001e8f        j___security_check_cookie(rax_1 ^ &var_2c8)
180001eb4        return result
```
we can see that ```j_sub_180002060``` is called three times so what is it ? 
it calls two functions :
this 
```c
1800013f0    uint64_t sub_1800013f0(int64_t arg1, 
1800013f0      int32_t arg2, void* arg3, 
1800013f0      int32_t arg4)

180001405        void var_138
180001405        int64_t rax_1 = __security_cookie ^ &var_138
180001410        int32_t zmm2[0x4] = data_180007930
18000141a        uint32_t zmm3[0x4] = data_180007950
180001422        void var_130
180001422        void* rdx = &var_130
18000142a        uint64_t i_3 = zx.q(arg4)
18000142d        int32_t rcx = 8
180001432        void* rbx = arg3
180001432        
1800014cc        do
180001447            rdx += 0x10
180001453            uint128_t zmm0 = _mm_add_epi32(_mm_shuffle_epi32(zx.o(rcx - 8), 0), zmm2)
180001460            int32_t rax_4 = rcx + 4
180001463            int32_t temp0_4[0x4] = _mm_add_epi32(_mm_shuffle_epi32(zx.o(rcx - 4), 0), zmm2)
180001467            zmm0 = _mm_and_ps(zmm0, zmm3)
18000146a            int32_t zmm1[0x4] = _mm_and_ps(temp0_4, zmm3)
18000146d            zmm0 = _mm_packus_epi16(zmm0, zmm0)
180001471            zmm1 = _mm_packus_epi16(zmm1, zmm1)
180001479            *(rdx - 0x18) = _mm_packus_epi16(zmm0, zmm0).d
180001482            *(rdx - 0x14) = _mm_packus_epi16(zmm1, zmm1)[0]
180001487            zmm0 = zx.o(rcx)
18000148b            rcx += 0x10
180001493            zmm0 = _mm_add_epi32(_mm_shuffle_epi32(zmm0, 0), zmm2)
18000149b            zmm1 = _mm_shuffle_epi32(zx.o(rax_4), 0)
1800014a0            zmm0 = _mm_and_ps(zmm0, zmm3)
1800014a3            int32_t temp0_15[0x4] = _mm_add_epi32(zmm1, zmm2)
1800014a7            zmm0 = _mm_packus_epi16(zmm0, zmm0)
1800014ab            zmm1 = _mm_and_ps(temp0_15, zmm3)
1800014b2            *(rdx - 0x10) = _mm_packus_epi16(zmm0, zmm0).d
1800014ba            zmm1 = _mm_packus_epi16(zmm1, zmm1)
1800014c2            *(rdx - 0xc) = _mm_packus_epi16(zmm1, zmm1)[0]
1800014cc        while (rcx - 8 u< 0x100)
1800014cc        
1800014d2        uint64_t r11 = 0
1800014d5        void* rcx_1 = &var_138
1800014d9        uint64_t rdi = 0
180001514        uint64_t result
180001514        
180001514        for (int32_t i = 0; i u< 0x100; )
1800014e0            char r9 = *rcx_1
1800014e4            rcx_1 += 1
1800014ed            uint64_t rdx_1 = zx.q(modu.dp.d(0:i, arg2))
1800014ef            i += 1
1800014fb            rdi = zx.q(*(rdx_1 + arg1) + rdi.b + r9)
180001502            result = zx.q(*(&var_138 + rdi))
180001506            *(rcx_1 - 1) = result.b
180001509            *(&var_138 + rdi) = r9
180001509        
180001516        uint64_t r9_1 = 0
180001519        uint64_t i_2 = i_3
180001519        
18000151f        if (i_3.d != 0)
180001574            uint64_t i_1
180001574            
180001574            do
180001534                r11 = zx.q((r11 + 1).b)
180001540                rbx += 1
180001544                char rdx_5 = *(&var_138 + r11)
18000154d                r9_1 = zx.q(r9_1.b + rdx_5)
180001556                *(&var_138 + r11) = *(&var_138 + r9_1)
18000155a                *(&var_138 + r9_1) = rdx_5
180001566                result = zx.q(*(&var_138 + r11) + rdx_5)
18000156d                *(rbx - 1) ^= *(&var_138 + result)
180001570                i_1 = i_2
180001570                i_2 -= 1
180001574            while (i_1 != 1)
180001574        
180001581        j___security_check_cookie(rax_1 ^ &var_138)
180001593        return result

```
which is SIMD implemnatition of RC4
and 
```c
180001630    int64_t sub_180001630(char* arg1, 
180001630      int64_t arg2)

180001638        int16_t* i = arg1
180001638        
18000163b        if (*arg1 != 0)
180001643            while (i u< &arg1[arg2 << 1])
180001645                i = &i[1]
180001645                
18000164d                if (*i == 0)
18000164d                    break
18000164d        
180001658        return j_sub_180001600(arg1, ((i - arg1) s>> 1) * 2) __tailcall
// and it is calling that
```
```c
180001600    int64_t sub_180001600(char* arg1, 
180001600      int64_t arg2)

180001600        int32_t result = 0x1505
180001600        
180001608        if (arg2 != 0)
180001622            int64_t i
180001622            
180001622            do
180001610                int32_t r8_1 = sx.d(*arg1)
180001614                arg1 = &arg1[1]
18000161b                result = (result * 0x21) ^ r8_1
18000161e                i = arg2
18000161e                arg2 -= 1
180001622            while (i != 1)
180001622        
180001624        return result

```
and this is the DJB2 hash function
so this function  
```j_sub_180002060(&var_298, 0x1a, &s, &data_180009000, 2, var_2a0)
```
is 
```c
180002060    int64_t _
DecryptRC4andCheckHashH(int64_t data, int64_t dataLength, char* dataa, int64_t key, int32_t keyLength, int32_t expected_hash)

180002081        memcpy(dest: dataa, src: data, count: dataLength.d)
180002093        RC4(key, keyLength, dataa, dataLength.d)
1800020b4        int32_t result
1800020b4        result.b = hash_utf16_string(dataa, dataLength u>> 1) == expected_hash
1800020bc        return result
```
which is simply 
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
    return 1
} else
{
return 0
}
```
so it is three stages decryptions
so for each stage we will get (key,key length, enc_data,length_enc_data)
### first Decryption :
```c
180001c86        if (_DecryptRC4andCheckHash(&var_298, 0x1a, &s, &data_180009000, 2, 0x6293def8) == 0)
```
so the length of the key is 2 , the key is data_180009000 
which we have 
```
data_180009001 = 0x6D ` and `data_180009000 = 0x7a `
```

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
result:
### second Decryption :
```c
180001c90            int32_t rax_3 = (*arg1)(&var_1f8)
180001c95            data_180009004 = ordd1
180001c9e            data_180009005 = ordd2
180001cae            data = 0x5ac1e9d0
180001cb6            data_180009003 = (rax_3 s>> 3).b ^ 0x36
180001cc6            data_180009006 = ordd3 ^ ordd1 ^ ordd2 ^ 0x10
180001cce            int32_t var_294_1 = 0x31280c9e
180001cdc            int32_t var_290
180001cdc            __builtin_strncpy(dest: &var_290, src: "X$]h", n: 4)
180001ce6            int32_t var_28c
180001ce6            __builtin_memcpy(dest: &var_28c, src: "\x54\x8d\x6f\xe7\xf6\xdb\xd7\xe5\xc0\x4b\x28\x46\xe7\xa4\x7e\xcd\x07\xf8\xf4\x41", n: 0x14)
180001d0e            void dataa
180001d0e            memset(dest: &dataa, c: 0, count: 0xc0)
180001d0e            
180001d43            if (_
DecryptRC4andCheckHash(&data, dataLength: 0x20, &dataa, key: &data_180009000, keyLength: 8, expected_hash: 0x69fa99d) == 0)
```
the encrypted data is missed here so i back to disassembely to see the real value of &data 
```assembely
180001cae  c7442430d0e9c15a   mov     dword [rsp+0x30 {data}], 0x5ac1e9d0
180001cb6  880d47730000       mov     byte [rel data_180009003], cl
180001cbc  80f310             xor     bl, 0x10
180001cbf  488d8dd0000000     lea     rcx, [rbp+0xd0 {dataa}]
180001cc6  881d3a730000       mov     byte [rel data_180009006], bl
180001ccc  33d2               xor     edx, edx  {0x0}
180001cce  c74424349e0c2831   mov     dword [rsp+0x34 {var_294_1}], 0x31280c9e
180001cd6  41b8c0000000       mov     r8d, 0xc0
180001cdc  c744243858245d68   mov     dword [rsp+0x38], 0x685d2458
180001ce4  8bf8               mov     edi, eax
180001ce6  c744243c548d6fe7   mov     dword [rsp+0x3c], 0xe76f8d54  {0xe76f8d54}
180001cee  c7442440f6dbd7e5   mov     dword [rsp+0x40 {var_288}], 0xe5d7dbf6  {0xe5d7dbf6}
180001cf6  c7442444c04b2846   mov     dword [rsp+0x44 {var_284}], 0x46284bc0
180001cfe  c7442448e7a47ecd   mov     dword [rsp+0x48 {var_280}], 0xcd7ea4e7  {0xcd7ea4e7}
180001d06  c744244c07f8f441   mov     dword [rsp+0x4c {var_27c}], 0x41f4f807
```
&data pointer starts at  `rsp+0x30`
it loads four bytes `mov     dword [rsp+0x30 {data}], 0x5ac1e9d0`
then `mov     dword [rsp+0x34 {var_294_1}], 0x31280c9e` another four bytes
then `mov     dword [rsp+0x3c], 0xe76f8d54  {0xe76f8d54}`
then `mov     dword [rsp+0x3c], 0xe76f8d54  {0xe76f8d54}`
...
then `mov     dword [rsp+0x4c {var_27c}], 0x41f4f807`
so encrypted data :
```c
uint8_t ciphertext[DATA_LEN] = {
0xd0,0xe9,0xc1,0x5a,0x9e,0x0c,0x28
,0x31,0x58,0x24,0x5d,0x68,0x54,0x8d
,0x6f,0xe7,0xf6,0xdb,0xd7,0xe5,0xc0
,0x4b,0x28,0x46,0xe7,0xa4,0x7e,0xcd
,0x07,0xf8,0xf4,0x41
    };
```
key length is `8` 
and the key :
```
data_180009000=0x7a
data_180009001=0x6d
data_180009002=0xcc
data_180009003=(key0to4 >> 3 )^0x36   
data_180009004=ord1
data_180009005=ord2
data_180009006=ordd3 ^ ordd1 ^ ordd2 ^ 0x10
data_180009007=0xcc
```
after brute forccing  i get 
```c
uint8_t key[8] = { 0x7a, 0x6d, 0xcc, 0x6f, 0x79 ,0x64 ,0x7f, 0xcc };

```
result :
### third Decryption :
in the same way i exctracted the encrypted data :
```c
ciphertext[DATA_LEN] = {
0xd6,0xe9,0xdd,0x5a,0x8e,0x0c,0x28
,0x31,0x43,0x24,0x59,0x68,0x5e,0x8d
,0x67,0xe7,0x91,0xdb,0xa2,0xe5,0xa0
,0x4b,0x31,0x46,0x90,0xa4,0x67,0xcd
,0x6b,0xf8,0xeb,0x41,0x20,0x94
};
```
and the same key  
```c
uint8_t key[8] = { 0x7a, 0x6d, 0xcc, 0x6f, 0x79 ,0x64 ,0x7f, 0xcc };
```
this decrypted to
`int(key[0:2])`






