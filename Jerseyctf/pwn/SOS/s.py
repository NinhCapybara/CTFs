data = open("sos_message.txt","rb").read()

bits = ""

i = 0
while i < len(data):
    # UTF-8 patterns
    if data[i:i+3] == b'\xe2\x80\x8b':
        bits += "0"
        i += 3
    elif data[i:i+3] == b'\xe2\x80\x8c':
        bits += "1"
        i += 3
    else:
        i += 1

print("bits:", len(bits))

msg = ""
for j in range(0, len(bits), 8):
    byte = bits[j:j+8]
    if len(byte) == 8:
        msg += chr(int(byte, 2))

print(msg)