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
i wasn't unterasted in those functions too much `{_logwtmp,_nextup,_creal,...}` as i know the author mapped the got table so in the chunk as im seeing that there is a lot of functions and solving that statically will be painful 
quick analyzis demonstrates that 
1-sub_17712 creates a 21×51 maze grid using a systematic wall placement algorithm
and this is the script (link)[link]
# Grid Union-Find Maze Generation Writeup

## Overview

The code analyzed implements a maze or grid generation algorithm using a disjoint-set (union-find) data structure to ensure all cells are connected without cycles. The logic ensures that the resulting structure has a unique path between any two points, forming a perfect maze.

## Grid Dimensions

The grid is represented as a 2D array with dimensions **21 rows × 51 columns**. It is initialized with alternating characters to form walls (`'#'`) and spaces (`' '`), depending on the parity of the row and column indices.

```assembly
for ( i = 1; i <= 49; ++i ) {
  if ( (i & 1) != 0 && (BYTE12(v17) & 1) != 0 )
    v5 = 32;
  else
    v5 = 35;
  *(_BYTE *)(*((_QWORD *)&v14 + 1) + 51LL * SHIDWORD(v17) + i) = v5;
```

Here, `i` runs from 1 to 49 (columns), but `i` is offset by 1 to account for inner paths. Including the outer walls (`i = 0` and `i = 50`), this defines **51 columns**. `SHIDWORD(v17)` controls the row index, iterating from 0 to 20 (inclusive), confirming the **21 rows**.

## Disjoint Set Union (Union-Find)

The code uses a disjoint-set data structure to track connectivity between cells. Two main helper functions are used:

### Find Operation (`sub_175FB`)

```c
if ( a1 == *(_DWORD *)(4LL * (int)a1 + a2) )
    return a1;
v3 = (unsigned int *)(4LL * (int)a1 + a2);
*v3 = sub_175FB(*v3, a2);
return *v3;
```

This implements path compression for the union-find structure.

### Union Operation (`sub_17673`)

```c
v6 = sub_175FB(a1, a3);
v5 = sub_175FB(a2, a3);
if ( v6 != v5 )
    *(_DWORD *)(a3 + 4LL * v5) = v6;
```

This merges two sets by updating the parent pointer.

### Index Mapping

Each space in the grid is mapped to a unique 1D index using:

```c
index = 25 * (row / 2) + (col / 2);
```

The use of `25` comes from half of the grid's size in the row dimension (since only every second row/column is a cell).

## Maze Generation Logic

### 1. Initialization

* Loop through the grid.
* Assign wall or space based on parity.
* Store potential edge walls between walkable cells.

```assembly
if ( (i & 1) != 0 && (BYTE12(v17) & 1) != 0 )
    v5 = 32; // space
else
    v5 = 35; // '#'
*(_BYTE *)(... + 51LL * row + col) = v5;
```

```assembly
if ((i & 1) == 0 && SHIDWORD(v17) % 2 == 1) {
  v6 = DWORD2(v17)++;
  v7 = (_DWORD *)(8LL * v6 + *(_QWORD *)fd);
  *v7 = HIDWORD(v17);
  v7[1] = i;
}
```

### 2. Edge Processing

Process each stored wall:

* Compute indices of the adjacent cells.
* If not connected, merge them and remove the wall.

```c
if ( (v25 & 1) != 0 ) {
    v22 = 25 * ((v24 - 1) / 2) + v25 / 2;
    v23 = 25 * ((v24 + 1) / 2) + v25 / 2;
} else {
    v22 = 25 * (v24 / 2) + (v25 - 1) / 2;
    v23 = 25 * (v24 / 2) + (v25 + 1) / 2;
}

if (sub_175FB(v22, v27) != sub_175FB(v23, v27)) {
    sub_17673(v22, v23, v27);
    *(_BYTE *)(v15 + 51LL * v24 + v25) = 32;
}
```

### 3. Finalization

After merging all possible walls without forming cycles, the final grid represents a maze with only one path between any two open cells.

```c
for ( j = 0; j < 250; ++j )
    *(_DWORD *)(v10 + 4LL * j) = j; // Disjoint-set parent array initialization
```

## Purpose

This technique ensures the generated grid:

* Has a path between any two walkable cells.
* Does not contain cycles (perfect maze).

This logic is commonly found in procedural maze generation techniques such as randomized Kruskal's algorithm.

## Note

Calls to functions like `_logwtmp`, `_nextup`, `_creal`, and others are ignored in this writeup as they appear to be irrelevant to the core logic, possibly added for obfuscation or to fill the call table.


2-sub_17A5F then solves the maze using breadth-first search to find the shortest path
and this is the (link)[link]
and it do the following: 
search_path: A pathfinding algorithm (like BFS or A*) that searches from a start node to a goal node (19, 49).

insert_node / pop_node: Abstracted priority queue operations.

Direction arrays (dx, dy) allow traversal in 4 cardinal directions.

It reconstructs the path if the goal is reached and returns its length, otherwise -1.

so it is a maze we have to find its size  , print it , find the start and end , solve it
### maze size :

to be true i stand at gdb for hours because those lines misunderstood me 
```assembely
.text:000000000001774E                 mov     [rbp-44h], 1        ; Start row = 1
.text:000000000001775A loc_1775A:
.text:000000000001775A                 mov     [rbp-40h], 1        ; Start column = 1
.text:0000000000017836 loc_17836:
.text:0000000000017836                 cmp     [rbp-40h], 31h      ; Column <= 49 (0x31)
.text:000000000001783A                 jle     loc_17766
.text:0000000000017840                 add     [rbp-44h], 1
.text:0000000000017844 loc_17844:
.text:0000000000017844                 cmp     [rbp-44h], 13h      ; Row <= 19 (0x13)
.text:0000000000017848                 jle     loc_1775A
```
because this shows that the grid size is 49*19 so i was solving for that and wondring why this is wrong until i reanlyzis again
    This loop fills columns 1 through 49 only.

    It skips column 0 and 50.

But the grid offset:

*(_BYTE *)(grid + 51LL * row + i)

means that each row is 51 bytes wide. That tells us something:
The size of each row is computed like this:

offset = 51 * row + i;

If i goes from 0 to 50, then a total of 51 characters (columns) are written per row.

So even if the loop fills only i = 1 to 49, we must assume:

    i = 0 (leftmost) and i = 50 (rightmost) are handled elsewhere in the code ( set as walls '#').

  so this confirms that the size is (51,21)

### finding the maze in fresh state  and prints it 
after by passing the first debug by patching and the second one (i patched it too for the first time but this was giving me the wrong puzzle ) so 
for the first time to pass the second anti debugging i did patched the `gdb,lldb` bytes but this was giving me the wrong puzzle because those bytes was used to control the maze state so set the rip to jump the the ptrace check when it hits `gdb` string 

and the best state for me was at input reading and guess what is read here ```_wordexp``` 
```assebmely
.text:0000000000018A6E                 mov     rdi, rax
.text:0000000000018A71                 call    sub_17A5F
.text:0000000000018A76                 mov     [rbp-6A48h], eax
.text:0000000000018A7C                 mov     byte ptr [rbp-672Dh], 20h ; ' '
.text:0000000000018A83                 mov     byte ptr [rbp-6365h], 20h ; ' '
.text:0000000000018A8A                 call    _wordexp

```
so i printed the dumped the maze  here 
set rax to zero `set $rax=0`
```assembely
   0x55555556c83a                  call   0x5555555673f0 <wprintf@plt>
●→ 0x55555556c83f                  test   rax, rax
   0x55555556c842                  je     0x55555556c858
   0x55555556c844                  mov    esi, 0x3
   0x55555556c849                  lea    rax, [rip+0x4b770]        # 0x5555555b7fc0
   0x55555556c850                  mov    rdi, rax
   0x55555556c853                  call   0x555555567890 <cimag@plt>
───────────────────────────────────────────────────────────────────────────
```
so breaking here now `.text:0000000000018A8A                 call    _wordexp`
and yes our puzzle is here 
```gef➤  x/gx $rbp-0x6760
0x7fffffff6e60:	0x2323232323232323
```
so i dumped it :
and this was the result 
```
###################################################
                          # #                 # # #
# ##### ### # # # ####### # # # ####### # ### # # #
#     # # # # # # #           # #     # #   #     #
# ### ### # # # ########### # # # # # ########### #
#   # #     # # # #   # # # # # # # #             #
# # # # # # # ### # # # # # ##### # # ### ##### # #
# # # # # # #       # # #   #   # # # #     #   # #
# # ### # # # # ##### # ### # ########### ####### #
# #   # # # # # #     #   # # # # # # # # # # # # #
######################### # # # # # # # # # # # # #
#                               #             # # #
####### ############# ##### # # # ### # ### ### # #
#             #         #   # # # #   #   #     # #
# # # # # ############# ###########################
# # # # # #                                       #
# ### # # # # ### # # # # # # # # # # ### ### ### #
#   # # # # #   # # # # # # # # # # #   #   # #   #
# # ##### # # # # ##### # # # # # ### # # # # # # #
# #     # # # # # #     # # # # #   # # # # # # #  
###################################################
```
to find the starting point i did the following 
```
gef➤  p 0x7fffffff6e93-0x00007fffffff6e60
$2 = 0x33 //51
gef➤  p $rbp-0x6365
$3 = (void *) 0x7fffffff725b
gef➤  
$4 = (void *) 0x7fffffff725b
gef➤  p 0x7fffffff725b-0x7fffffff6e60
$5 = 0x3fb //1019
gef➤  
```
row = 51 // 51 = 1
col = 51 % 51 = 0
→ Coordinate: (1, 0)
row = 1019 // 51 = 19
col = 1019 % 51 = 50
→ Coordinate: (19, 50)
and we solve the puzzle for that (script.py)[link]
```from collections import deque
k=open("./f8.txt","rb").read()
maze_text='\n'.join(k[i:i+51].decode('latin1') for i in range(0, len(k), 51))
# Convert string to 2D grid
maze = [list(row) for row in maze_text.splitlines()]
H, W = len(maze), len(maze[0])
def neighbors(r, c):
    for dr, dc, d in [(-1, 0, 0b00), (1, 0, 0b01), (0, -1, 0b10), (0, 1, 0b11)]:
        nr, nc = r + dr, c + dc
        if 0 <= nr < H and 0 <= nc < W and maze[nr][nc] != '#':
            yield (nr, nc), d

def bfs(start, end):
    queue = deque([(start, [])])
    visited = set([start])
    while queue:
        (r, c), path = queue.popleft()
        if (r, c) == end:
            return path
        for (nr, nc), direction in neighbors(r, c):
            if (nr, nc) not in visited:
                visited.add((nr, nc))
                queue.append(((nr, nc), path + [direction]))
    return None

def path_to_hex(bits):
    b = 0
    out = []
    for i, d in enumerate(bits):
        b = (b << 2) | d
        if (i+1) % 4 == 0:
            out.append(f"{b:02x}")
            b = 0
    if len(bits) % 4 != 0:
        b <<= (4 - len(bits) % 4) * 2
        out.append(f"{b:02x}")
    return ''.join(out)

# ✅ Define start and end (row, col)
start = (1, 0)
end = (19,50 )

path = bfs(start, end)
if path:
    print("Path in hex:", path_to_hex(path))
else:
    print("No path found")
```
and yes that is it `ffffffffffffd7d5556aa97d7ffffffffffffd57`















