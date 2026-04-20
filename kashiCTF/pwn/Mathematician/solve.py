#!/usr/bin/env python3

from pwn import *

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



        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('34.126.223.46', 17780)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

for _ in range(100):
    p.recvuntil(b'I GIVE: ')
    number = int(p.recvline().strip())
    success(f"number: {int(number)}")
    slna(b'YOU GIVE: ', number + 10)
    success(f"number send: {int(number+10)}")
    
p.interactive()
