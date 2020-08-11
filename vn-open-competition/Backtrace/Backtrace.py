# !/usr/bin/env/python3
import random


flag = "flag{" + ''.join(str(random.getrandbits(32)) for _ in range(4)) + "}"

with open('output.txt', 'w') as f:
    for i in range(1000):
        f.write(str(random.getrandbits(32)) + "\n")

print(flag)