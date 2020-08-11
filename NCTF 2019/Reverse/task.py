import os
import pyDes


flag = "NCTF{******************************************}"
key = os.urandom(8)

d = pyDes.des(key)
cipher = d.encrypt(flag.encode())

with open('cipher', 'wb') as f:
    f.write(cipher)

# Leak: d.Kn[10] == [0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1]