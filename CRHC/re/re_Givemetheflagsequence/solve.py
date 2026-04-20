import pexpect

flag = [0]*42
for i in range(42):
    for c in range(32,127):
        candidate = flag[:]
        candidate[i] = c
        inp = " ".join(f"{b:02x}" for b in candidate) + "\n"

        child = pexpect.spawn("./chal")   # chạy trực tiếp binary, không cần gdb
        child.expect("please enter your flag sequence")
        child.send(inp)
        child.expect(["Correct!", "Incorrect!"], timeout=2)

        out = child.after.decode()
        child.close()

        if "Correct!" in out:
            flag[i] = c
            print(f"Found {i}: {chr(c)}")
            break

print("Flag:", "".join(chr(c) for c in flag))
