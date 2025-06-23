# Reverse Engineering - Complete Guide

## What is Reverse Engineering?

Reverse engineering is the process of analyzing a system to understand how it works.

## What Can Be Reversed?

* **Software:** Programs, mobile apps, games
* **Hardware:** Circuit boards, electronic devices
* **File Formats:** Unknown data structures
* **Protocols:** Communication mechanisms between systems

In this session, our focus is on reversing **software (programs)**.

To reverse something effectively, you need to understand how it was built.

---

## Programming Language Types

### 1. Compiled Languages

* **Definition:** Code is translated entirely into machine code (binary) before execution.
* **Execution:** The binary is platform-specific and runs directly on the CPU.
* **Examples:** C, C++, Rust, Go
* **Process:**
  * Source Code (.c) → Compiler → Machine Code (.exe or binary) → CPU executes
* **Pros:**
  * Fast execution
  * No interpreter needed at runtime
* **Cons:**
  * Requires compilation step
  * Less flexible for dynamic tasks

### 2. Interpreted Languages

* **Definition:** Code is executed line-by-line by an interpreter without prior compilation.
* **Examples:** Python, JavaScript, Ruby, PHP
* **Process:**
  * Source Code (.py) → Interpreter → Direct Execution
* **Pros:**
  * Easy to test and debug
  * Portable across different platforms
* **Cons:**
  * Slower execution
  * Requires interpreter on the system

### 3. Mixed (Compiled + Interpreted)

Some languages use both compiled and interpreted techniques.

* **Examples:**
  * **Java:** Compiles to bytecode, then runs on the JVM (interpreted or JIT compiled)
  * **Python:** Compiles to bytecode, then runs on the CPython interpreter

---

## Python Execution Pipeline

### Read the source code (print("Hello"))
- Load the .py file or the input code from terminal
- Convert it into a stream of characters

### Lexing (Tokenization)
- Turns code into tokens:
  ```
  NAME('print') STRING("Hello")
  ```

### Parsing
- Uses grammar rules to build an AST (Abstract Syntax Tree):
  ```
  Call(
    func=Name(id='print'),
    args=[Constant(value='Hello')]
  )
  ```

### Compilation to Bytecode
- Converts AST into low-level bytecode instructions, like:
  ```
  LOAD_NAME    'print'
  LOAD_CONST   'Hello'
  CALL_FUNCTION
  ```

### Interpretation (Execution)
- Uses a virtual machine loop (often a switch-case or function pointer table in C) to run each bytecode instruction.
- E.g., when it sees CALL_FUNCTION, it calls the actual print() function (written in C).

---

## C Compilation Pipeline (C → Assembly)

When you compile a C file (e.g., hello.c) using gcc, it passes through these main stages:

### 1. Preprocessing (.i file)
- Handles all #include, #define, #ifdef macros.
- Expands header files and macros.
- Removes comments.

**Command:**
```bash
gcc -E hello.c -o hello.i
```
**Output:** a plain C file with headers/macros expanded.

### 2. Compilation (.s file)
- Translates the C code into assembly language.
- Generates architecture-specific instructions (e.g., x86-64 or ARM).

**Command:**
```bash
gcc -S hello.i -o hello.s
```
or directly:
```bash
gcc -S hello.c -o hello.s
```
**Output:** an assembly (.s) file (e.g., mov, call, ret instructions)

### 3. Assembly (.o file)
- Assembler converts .s (text) to machine code bytes (binary).
- This is now executable code, but not linked yet.

**Command:**
```bash
gcc -c hello.s -o hello.o
```
or:
```bash
gcc -c hello.c -o hello.o
```
**Output:** .o (object file), which contains binary machine code, relocations, and symbol info.

### 4. Linking (final executable)
- Links .o with standard libraries (like libc) and your other object files.
- Resolves all symbol references (printf, main, etc.)
- Produces a complete executable (ELF on Linux, PE on Windows).

**Command:**
```bash
gcc hello.o -o hello
```
or directly in one shot:
```bash
gcc hello.c -o hello
```
**Output:** hello → a binary file your OS can run.
