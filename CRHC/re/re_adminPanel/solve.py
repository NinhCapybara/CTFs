#!/usr/bin/env python3
with open("Admin_Panel","rb") as f: data = bytearray(f.read())
data[0x1ab6] = 0x74
open("Admin_Panel_patched","wb").write(data)
print("YES")