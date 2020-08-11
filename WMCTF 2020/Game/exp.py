# !/usr/bin/env python3
import re, string
from hashlib import sha256
from itertools import product

from pwn import *

def xor(a, b):
    return bytes(x^y for x, y in zip(a, b))

def hex2bytes(data):
    return bytes.fromhex(data.decode())


# r = remote("127.0.0.1", 10000)
r = remote("81.68.174.63", 16442)
# context.log_level = 'debug'

# PoW
r.recvlines(13) # banner
rec = r.recvline().decode()
suffix = re.findall(r'XXXX\+([^\)]+)', rec)[0]
digest = re.findall(r'== ([^\n]+)', rec)[0]
print(f"suffix: {suffix} \ndigest: {digest}")
print('Calculating hash...')
for i in product(string.ascii_letters + string.digits, repeat=4):
    prefix = ''.join(i)
    guess = prefix + suffix
    if sha256(guess.encode()).hexdigest() == digest:
        print(guess)
        break
r.sendafter(b'Give me XXXX: ', prefix.encode())

# Attack
rec = r.recvline().decode()
IV_hex = re.findall(r'([0-9a-f]{32})', rec)[0]
IV = bytes.fromhex(IV_hex)

def getLastBit(known, cipher, IV):
    """
    known: first 15 bytes that we know

    cipher: Ek(known + ?) where ? is one byte that we want to get

    returns (?, IV)
    """
    for i in range(256):
        r.sendlineafter(b"> ", b"1")
        payload = xor(IV, known + bytes([i]))  # Ek(known + i) where len(known) = 15, len(i) = 1
        r.sendlineafter(b"(in hex): ", payload.hex().encode())

        rec = r.recvline(keepends=False)
        IV = hex2bytes(rec[-16*2:])
        if hex2bytes(rec[:16*2]) == cipher:
            return bytes([i]), IV
    return None

# Recover byte by byte.
recovered = b""
for k in range(4):
    # k=0: secret[0:15]   l={15, 14, ..., 1}
    # k=1: secret[15:31]  l={16, 15, ..., 1}
    # k=2: secret[31:47]  l={16, 15, ..., 1}
    # k=3: secret[47:48]  l={16}
    start = 15 if k == 0 else 16
    end   = 15 if k == 3 else 0
    for l in range(start, end, -1):
        r.sendlineafter(b"> ", b"1")
        r.sendlineafter(b"(in hex): ", IV[:l].hex().encode())
        rec = hex2bytes(r.recvline(keepends=False))
        if k == 0:
            known = b"\x00"*l + xor(IV[l:-1], recovered)
            last_byte = IV[-1:]
            cipher, IV = rec[:16], rec[-16:]
        else:
            known_IV, cipher, IV = rec[16*(k-1):16*k], rec[16*k:16*(k+1)], rec[-16:]
            known = xor(known_IV, recovered[-15:])
            last_byte = known_IV[-1:]

        byte, IV = getLastBit(known, cipher, IV)
        recovered += xor(byte, last_byte)
        print(recovered.hex(), len(recovered))

# Get flag.
r.sendlineafter(b"> ", b"2")
r.sendlineafter(b"(in hex): ", recovered.hex().encode())
print(r.recvline(keepends=False))
# b'TQL!!! Here is your flag: WMCTF{Dont_ever_tell_anybody_anything___If_you_do__you_start_missing_everybody}'

r.close()
