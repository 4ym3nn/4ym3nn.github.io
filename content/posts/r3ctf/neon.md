+++
date = '2025-07-09T22:29:05+01:00'
draft = false
title = 'Past'
+++

![image](https://github.com/user-attachments/assets/06eaaa2f-5e52-4112-9111-3fc2e4019e77)

# Neon Deceit
**15 solves | Reverse**

## Challenge Description
In the neon-lit underbelly of the city, even your tools are programmed to betray you. Trust nothing... the lies are embedded in the code.

## Initial Analysis

Starting with the binary from R3CTF, I ran it to see what happens:

```bash
➜  neon_deceit ./neon_deceit 
hello world
➜  neon_deceit 
```

That's weird - a simple "hello world" program that's 400KB? Something's definitely not right here.

```bash
➜  neon_deceit ls -l neon_deceit
-rwxrwxrwx 1 user user 407640 Jul  4 15:40 neon_deceit
➜  neon_deceit 
```

A basic hello world program shouldn't be nearly half a megabyte. Time to dig into the decompilation and see what's really going on.

## Decompilation in IDA

Opening the binary in IDA, the main function looks pretty standard:

```c
void **fastcall **noreturn main(int a1, char **a2, char **a3)
{
  puts("hello world");
  exit(0);
}
```

The assembly is equally straightforward:

```assembly
; void **fastcall **noreturn main(int, char **, char **)
main proc near
var_4= dword ptr -4
; __unwind {
endbr64
push    rbp
mov     rbp, rsp
sub     rsp, 10h
mov     [rbp+var_4], edi
lea     rax, s          ; "hello world"
mov     rdi, rax        ; s
call    _puts
mov     edi, 0          ; status
call    _exit
main endp
```

Nothing suspicious here, so I decided to debug it. I set a breakpoint at puts and stepped through to see what happens at exit.

![image](https://github.com/user-attachments/assets/385eaedb-8d3e-4fa7-8316-f916043c343a)

After hitting the exit call and using `ni`:

![image](https://github.com/user-attachments/assets/a8c14568-f632-40a0-abcd-6ea17c17571c)

Wait, we passed the exit? That's not supposed to happen. What's going on here?

## The PLT Hijacking Trick

This is where things get interesting. The binary is using a clever technique to fool static analysis tools.

### How PLT Hijacking Works

#### 1. Disassembler Labeling
Disassemblers name each PLT stub (like `exit@plt`) based purely on the ELF symbol table. They don't bother re-examining the stub's actual immediate values or relocation indices.

#### 2. Normal PLT/GOT Resolution
Here's how it normally works:
1. **PLT stub** pushes its relocation index (say, for `exit`)
2. Jumps to the dynamic linker
3. **Linker** resolves the symbol in libc, writes the real address into the **corresponding GOT slot**
4. Future calls jump directly to that GOT entry

#### 3. The Patch
By changing the `push <reloc_index>` immediate in the PLT stub:

```diff
- push  <reloc_index_for_exit>
+ push  <reloc_index_for_foo>
```

You're telling the linker to resolve `foo` instead of `exit`. The disassembler still shows it as `exit@plt`, but at runtime it's actually calling whatever function corresponds to that new relocation index.
let us back to the disassembely
```.text:00000000000596D8 ; void __fastcall __noreturn main(int, char **, char **)
.text:00000000000596D8 main            proc near               ; DATA XREF: start+18↑o
.text:00000000000596D8
.text:00000000000596D8 var_4           = dword ptr -4
.text:00000000000596D8
.text:00000000000596D8 ; __unwind {
.text:00000000000596D8                 endbr64
.text:00000000000596DC                 push    rbp
.text:00000000000596DD                 mov     rbp, rsp
.text:00000000000596E0                 sub     rsp, 10h
.text:00000000000596E4                 mov     [rbp+var_4], edi
.text:00000000000596E7                 lea     rax, s          ; "hello world"
.text:00000000000596EE                 mov     rdi, rax        ; s
.text:00000000000596F1                 call    _puts
.text:00000000000596F6                 mov     edi, 0          ; status
.text:00000000000596FB                 call    _exit
.text:00000000000596FB main            endp
.text:00000000000596FB
.text:0000000000059700 ; ---------------------------------------------------------------------------
.text:0000000000059700                 cmp     dword ptr [rbp-4], 7
.text:0000000000059704                 jnz     short loc_59712
.text:0000000000059706                 mov     eax, 0
.text:000000000005970B                 call    sub_18597
```
so we are storing the number of args `argc` in `rbp-4` compare it to 7 if equal jump to the real main function else  it will jump here and exit 
```
.text:0000000000059712
.text:0000000000059712 loc_59712:                              ; CODE XREF: .text:0000000000059704↑j
.text:0000000000059712                 lea     rax, s          ; "hello world"
.text:0000000000059719                 mov     rdi, rax
.text:000000000005971C                 call    _realloc
.text:0000000000059721                 mov     edi, 0
.text:0000000000059726                 call    _pututxline
.text:000000000005972B
```
and yes running with `neon_deceit ./neon_deceit 1 2 3 4 5 6` asks for key 
![image](https://github.com/user-attachments/assets/0c144177-16c9-48a3-8b47-a26e23717e75)
let us open the real main function   [main.c](https://github.com/4ym3nn/4ym3nn.github.io/blob/master/content/posts/r3ctf/main_logic.c) 
so let us go through analyzing ,i used `ltrace` to track dynamic libary calls and 
```bash
➜  neon_deceit ltrace ./neon_deceit 1 2 3 4 5 6
strdup("hello world")                                                   = 0x555f21c802a0
sleep(0)                                                                = 0
ptrace(0, 0, 1, 0)                                                      = -1
longjmp(0x555f16a74fc0, 2, 0, 0x7f5f044e1888 <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
➜  neon_deceit
```
ptrace so antidebugging is present here now i should find where it is again with gdb `break ptrace  `
and logging the backtrace 
```
────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff76e1830 → ptrace(request=PTRACE_TRACEME)
[#1] 0x55555556c5ec → test rax, rax
[#2] 0x5555555ad710 → jmp 0x5555555ad72b
```
so ```test rax,rax``` is checking if antidebugger is present analyzing the offset 
![image](https://github.com/user-attachments/assets/18aab588-a4fb-4a04-98a4-49a28f4e0a5d)
and yeah guess what `call    _vfwprintf` is `call ptrace `
checking for debugger logic is here
```
call    _vfwprintf
test    rax, rax
jns     short loc_18605
```
so i patched the `jns` to `js` and focus that the exit is `cimg`
```
.text:00000000000185E7                 call    _vfwprintf
.text:00000000000185EC                 test    rax, rax
.text:00000000000185EF                 jns     short loc_18605
.text:00000000000185F1                 mov     esi, (offset dword_0+2) ; modes
.text:00000000000185F6                 lea     rax, dirp
.text:00000000000185FD                 mov     rdi, rax
.text:0000000000018600                 call    _cimag
```
running `ltrace` again :
```
➜  neon_deceit ltrace ./neon_deceit 1 2 3 4 5 6
strdup("hello world")                                                                                                                              = 0x5630660542a0
sleep(0)                                                                                                                                           = 0
ptrace(0, 0, 1, 0)                                                                                                                                 = -1
getppid()                                                                                                                                          = 19161
snprintf("/proc/19161/comm", 4096, "/proc/%d/comm", 19161)                                                                                         = 16
fopen("/proc/19161/comm", "r")                                                                                                                     = 0x5630660542c0
fread(0x7ffc53f4a7f0, 1, 1023, 0x5630660542c0)                                                                                                     = 7
fclose(0x5630660542c0)                                                                                                                             = 0
strstr("ltrace\n", "gdb")                                                                                                                          = nil
strstr("ltrace\n", "lldb")                                                                                                                         = nil
strstr("ltrace\n", "ida")                                                                                                                          = nil
strstr("ltrace\n", "strace")                                                                                                                       = nil
strstr("ltrace\n", "ltrace")                                                                                                                       = "ltrace\n"
longjmp(0x5630641e1fc0, 3, 0, 114 <no return ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
➜  neon_deceit 
```
now after we passedd the first antidebug part
```c

    // Attempt initial wide printf
    writeStatus = vfwprintf(NULL, NULL, (char *)&dword_0 + 1);
    if (writeStatus >= 0) {
        streamMode = (char *)&dword_0 + 2;
        cimag(&dirp, streamMode);
    }

    memset(fd, 0, sizeof(fd));
    fileDescriptor = (unsigned int)fdopen((int)&fdWrapper, streamMode);

    csqrtl(processBuffer, 4096LL, "/proc/%d/comm", fileDescriptor);
    priorityLine = (char *)sched_get_priority_min((int)processBuffer);
```
let us look to the second
```c

    if (priorityLine) {
        input1 = fmod(input1, input2);

        logwtmp(priorityLine, (_BYTE *)&dword_0 + 1, dummy);

        // Load XOR-encoded strings
        encodedStrings[0] = &unk_63F78; encodedStrings[1] = 3LL;
        encodedStrings[2] = &unk_63F7B; encodedStrings[3] = 4LL;
        encodedStrings[4] = &unk_63F7F; encodedStrings[5] = 3LL;
        encodedStrings[6] = &unk_63F82; encodedStrings[7] = 6LL;
        encodedStrings[8] = &unk_63F88; encodedStrings[9] = 6LL;
        encodedStrings[10] = &unk_63F8E; encodedStrings[11] = 7LL;
        encodedStrings[12] = &unk_63F95; encodedStrings[13] = 2LL;

        for (i = 0; i <= 6; ++i) {
            displayData = encodedStrings[2 * i];
            dataLength = encodedStrings[2 * i + 1];
            for (j = 0; j < dataLength; ++j)
                decoded[j] = *(_BYTE *)(displayData + j) ^ 0x5A; // XOR decryption
            decoded[dataLength] = 0;

            printStatus = wprintf(format, decoded);
            if (printStatus)
                cimag(&dirp, 3LL);
        }
    }
```
it is equaivalent to that 
```c
char xor_decrypt_char(char c) {
    return c ^ 0x5A;
}

void decrypt_and_print(const char *label, const unsigned char *data, int length) {
    printf("%s: ", label);
    for (int i = 0; i < length; ++i) {
        putchar(xor_decrypt_char(data[i]));
    }
    putchar('\n');
}

int main() {
    decrypt_and_print("unk_63F78", (unsigned char[]){0x3D, 0x3E, 0x38}, 3);              // =>8 => gdb
    decrypt_and_print("unk_63F7B", (unsigned char[]){0x36, 0x36, 0x3E, 0x38}, 4);        // 66>8 => lldb
    decrypt_and_print("unk_63F7F", (unsigned char[]){0x33, 0x3E, 0x3B}, 3);              // 3>; => ida
    decrypt_and_print("unk_63F82", (unsigned char[]){0x29, 0x2E, 0x28, 0x3B, 0x39, 0x3F}, 6); // )..(;9? => strace
    decrypt_and_print("unk_63F88", (unsigned char[]){0x36, 0x2E, 0x28, 0x3B, 0x39, 0x3F}, 6); // 6.(;9? => ltrace
    decrypt_and_print("unk_63F8E", (unsigned char[]){0x28, 0x3B, 0x3E, 0x3B, 0x28, 0x3F, 0x68}, 7); // (;>;(?h => radare2
    decrypt_and_print("unk_63F95", (unsigned char[]){0x28, 0x68}, 2);                    // (h => r2

    return 0;
}
```
so it decrypts the data then called the ptrace `vwprintf` if debugger is present call cimg `exit`
```c
            printStatus = wprintf(format, decoded);
            if (printStatus)
                cimag(&dirp, 3LL);
        }
```
okay so after that i saw this section 
```assembely
.text:00000000000189D8 main_check      endp ; sp-analysis failed
.text:00000000000189D8
.text:00000000000189DD ; ---------------------------------------------------------------------------
.text:00000000000189DD                 test    rax, rax
.text:00000000000189E0                 jnz     loc_188F5
.text:00000000000189E6                 mov     rax, [rbp-69E0h]
.text:00000000000189ED                 mov     rdi, rax
.text:00000000000189F0                 call    _logwtmp
.text:00000000000189F5                 mov     rax, [rbp-69E8h]
.text:00000000000189FC                 mov     rdi, rax
.text:00000000000189FF                 call    _nextup
.text:0000000000018A04                 lea     rdx, [rbp-68B0h]
.text:0000000000018A0B                 lea     rax, [rbp-5ED0h]
.text:0000000000018A12                 mov     rsi, rdx
.text:0000000000018A15                 mov     rdi, rax
.text:0000000000018A18                 call    _creal
.text:0000000000018A1D                 lea     rax, [rbp-5ED0h]
.text:0000000000018A24                 lea     rcx, [rax+1Ch]
.text:0000000000018A28                 lea     rax, [rbp-6930h]
.text:0000000000018A2F                 mov     edx, 4
.text:0000000000018A34                 mov     rsi, rcx
.text:0000000000018A37                 mov     rdi, rax
.text:0000000000018A3A                 call    _getpgid
.text:0000000000018A3F                 mov     eax, [rbp-6930h]
.text:0000000000018A45                 mov     [rbp-6A40h], eax
.text:0000000000018A4B                 mov     eax, [rbp-6A40h]
.text:0000000000018A51                 mov     edi, eax
.text:0000000000018A53                 call    _cfsetispeed
.text:0000000000018A58                 lea     rax, [rbp-6760h]
.text:0000000000018A5F                 mov     rdi, rax
.text:0000000000018A62                 call    sub_17712
.text:0000000000018A67                 lea     rax, [rbp-6760h]
.text:0000000000018A6E                 mov     rdi, rax
.text:0000000000018A71                 call    sub_17A5F
.text:0000000000018A76                 mov     [rbp-6A48h], eax
.text:0000000000018A7C                 mov     byte ptr [rbp-672Dh], 20h ; ' '
.text:0000000000018A83                 mov     byte ptr [rbp-6365h], 20h ; ' '
.text:0000000000018A8A                 call    _wordexp
.text:0000000000018A8F                 call    _getloadavg
.text:0000000000018A94                 call    _sqrtl
.text:0000000000018A99                 mov     edi, 0
.text:0000000000018A9E                 call    _nexttoward
.text:0000000000018AA3                 lea     rax, dirp
.text:0000000000018AAA                 mov     rdi, rax
.text:0000000000018AAD                 call    _rintl
.text:0000000000018AB2                 endbr64
.text:0000000000018AB6                 test    eax, eax
.text:0000000000018AB8                 jz      short loc_18AD8
.text:0000000000018ABA                 call    _frexpf
.text:0000000000018ABF                 lea     rax, aAccessDenied ; "Access Denied."
.text:0000000000018AC6                 mov     rdi, rax
.text:0000000000018AC9                 call    _realloc
.text:0000000000018ACE                 mov     eax, 1
.text:0000000000018AD3                 jmp     loc_596C2
.text:0000000000018AD8 ; ---------------------------------------------------------------------------
```
i wasn't unterasted in those functions too much `{_logwtmp,_nextup,_creal,...}` as i know the author mapped the got table  so i will look to the subroutines 
starting by this `sub_17712`
 w
