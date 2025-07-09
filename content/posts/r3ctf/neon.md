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
another antidebugging check let us identify this part in code so it here 
so 
