key = 42

data = bytes.fromhex(open("hex.txt").read())

decoded = bytes((b - key) % 256 for b in data)

open("flag.bin", "wb").write(decoded)