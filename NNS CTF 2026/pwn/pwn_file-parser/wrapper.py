import base64
import subprocess
import os

file = input("Send over your file as base64: ")

path = f"/tmp/{os.urandom(8).hex()}.k"
with open(path, "wb") as f:
    f.write(base64.b64decode(file))

os.execve("./fileparser", ["./fileparser", path], os.environ.copy())