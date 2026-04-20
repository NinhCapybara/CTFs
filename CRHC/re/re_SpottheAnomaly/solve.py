path = "chal"
off = 0x12c7
n = 0x22
data = open(path,"rb").read()[off:off+n]
print(bytes([b ^ 0x23 for b in data]).decode())
