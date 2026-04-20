import hashlib
import base64

# === PART 1 ===
# s[4:8] có MD5 == 33635414851f62863a5cb7825481433d
# brute 4 ký tự ASCII dễ (62^4 = 14M)

import itertools
import string

md5_target = "33635414851f62863a5cb7825481433d"

def find_md5_part():
    chars = string.ascii_letters + string.digits
    for p in itertools.product(chars, repeat=4):
        candidate = "".join(p)
        h = hashlib.md5(candidate.encode()).hexdigest()
        if h == md5_target:
            return candidate
    return None

part_md5 = "Wh4t"   # đã tìm được từ lần trước, không brute nữa


# === PART 2 ===
# s[8:12] hex == "5f345f46" → bytes = b"_4_F"
part_hex = "_4_F"

# === PART 3 ===
# Base64(s[12:16]) == "dW5ueQ==" → "unny"
part_b64 = base64.b64decode("dW5ueQ==").decode()

# === PART 4 ===
# s[16] = '_'
# s[17] ^ 5 == 'r'  → 'w'
# s[18] = '4'
# ord(s[19]) == 0x79 → 'y'
part4 = "_w4y"

# === PART 5 ===
# SHA256(s[20:24]) = c1cd3414aea97cfb005cf3bf3f39f3c1b5412f5dd8a2602c74a38181d94f5a2d
part_sha256 = "_t0_"   # đã tìm sẵn

# === PART 6 ===
# Base32(s[24:29]) == "MNUDGY3L" → decode ngược ra "ch3ck"
part_base32 = "ch3ck"

# === PART 7 ===
# s[29] = '_'
# ord(s[30]) bin == 0b1100110 → 'f'
# s[31] = '0'
# s[32] = 'R'
part7 = "_f0R"

# === PART 8 ===
# s[33:36] == "_4_"
part8 = "_4_"

# === PART 9,10,11 ===
# (s[37] ^ s[38]) == 1
# s[37] == '4'
# int(s[39]) + 10 == 15 → s[39] = '5'
part9_10_11 = "p455"  # 'p', '4', '5', '5'

# === PART 12 ===
# s[40] == 'w'
part12 = "w"

# === PART 13 ===
# hex of s[41:] == "3072647d" → "0rd}"
part13 = "0rd}"

# === Assemble all ===

flag = (
    "ptm{" +
    part_md5 +
    part_hex +
    part_b64 +
    part4 +
    part_sha256 +
    part_base32 +
    part7 +
    part8 +
    part9_10_11 +
    part12 +
    part13
)

print(flag)
