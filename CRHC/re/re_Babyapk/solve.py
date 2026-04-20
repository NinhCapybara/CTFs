from base64 import b64decode
from Crypto.Cipher import AES

key = b"6c77a920b3232ef5"
iv  = b"a36edc9a25527dbc"

ciphertext = b64decode("/Ht9CWzMAB1eeQVhMTnAEDVJHUzL77Iuiil3uUiR12E=")

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)

# loại bỏ padding PKCS#5
pad_len = plaintext[-1]
flag = plaintext[:-pad_len].decode("utf-8")
print(flag)
