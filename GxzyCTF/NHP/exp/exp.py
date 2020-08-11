import re
import json
import string
import subprocess
from random import sample
from hashlib import sha256

from Crypto.Util.number import inverse
from pwn import *



host, port = ('127.0.0.1', 10000)
r = remote(host, port)
# context.log_level = 'debug'


# Proof of Work
rec = r.recvline().decode()

suffix = re.findall(r'\+ ([0-9a-f]*?)\)', rec)[0]
digest = re.findall(r'== ([0-9a-f]*?)\n', rec)[0]
print(f"suffix: {suffix} \ndigest: {digest}")

for i in range(256**3):
    guess = i.to_bytes(3, 'big') + bytes.fromhex(suffix)
    if sha256(guess).hexdigest() == digest:
        print('[!] Find: ' + guess.hex())
        break
else:
    print('Not found...')

r.sendlineafter(b'Give me XXX in hex: ', guess[:3].hex().encode())

# DSA params
params = r.recvuntil(b'3. exit\n').decode()
p = int(re.findall(r'p = ([0-9]*?)\n', params)[0])
q = int(re.findall(r'q = ([0-9]*?)\n', params)[0])
g = int(re.findall(r'g = ([0-9]*?)\n', params)[0])
y = int(re.findall(r'y = ([0-9]*?)\n', params)[0])
print(f"p: {p}\nq: {q}\ng: {g}\ny: {y}")


# Interactive
Hm_s = []
r_s = []
s_s = []

s = string.ascii_letters + string.digits
cnt = 0
total = 0
while cnt < 40:
    total += 1
    name = ''.join(random.sample(s, 10)).encode()
    r.sendlineafter(b"$ ", b"1")
    r.sendlineafter(b"Please input your username: ", name)

    rec = r.recvuntil(b"3. exit\n").decode()
    k_bits = int(re.findall(r"== ([0-9]*?)\n", rec)[0])
    if k_bits < 122:
        cnt += 1

        data = re.findall(r"in hex: ([0-9A-Z]*?)\n", rec)[0]
        sig = bytes.fromhex(data)
        (name, sig_r, sig_s) = (sig[:-40], sig[-40:-20], sig[-20:])
        (sig_r, sig_s) = map(lambda x: int.from_bytes(x, 'big'), (sig_r, sig_s))

        print(f"\ncount: {cnt}\nk_bits: {k_bits}")
        print(f"sig_r: {sig_r}\nsig_s: {sig_s}")

        Hm = int.from_bytes(sha256(name).digest(), 'big')
        Hm_s.append(Hm)
        r_s.append(sig_r)
        s_s.append(sig_s)

print(f"\nTotal times: {total}")

# save data
f = open('data', 'w')
json.dump([q, Hm_s, r_s, s_s], f)
f.close()

# solve HNP
print("\nSolving HNP...")
cmd = "sage solver.sage"
try:
    res = subprocess.check_output(cmd.split(' '))
except:
    print("Can't find x...")
    exit(1)
x = int(res)

# check
assert(y == pow(g, x, p))
print(f"find x: {x}")

# forge signature
admin = b"admin"
Hm = int.from_bytes(sha256(admin).digest(), 'big')
k = 0xdeadbeef
k_inv = inverse(k, q)
sig_r = pow(g, k, p) % q
sig_s = (k_inv * (Hm + x*sig_r)) % q

# sign in
sig = admin + sig_r.to_bytes(20, 'big') + sig_s.to_bytes(20, 'big')
print(f"Sending signature: {sig.hex().upper()}")
r.sendlineafter(b'$ ', b"2")
r.sendlineafter(b'Please send me your signature: ', sig.hex().upper().encode())


r.interactive()
