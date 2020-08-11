#!/usr/bin/env python3
import os
from random import SystemRandom
from string import ascii_letters, digits
from hashlib import sha256

from Crypto.Util import number

from flag import FLAG


random = SystemRandom()


def proof_of_work():
    s = os.urandom(10)
    digest = sha256(s).hexdigest()
    print(f"sha256(XXX + {s[3:].hex()}) == {digest}")
    try:
        x = input("Give me XXX in hex: ")
    except:
        print("Invalid input!")
        return False

    if len(x) != 6 or x != s[:3].hex():
        print("Wrong XXX!")
        return False
    return True

def genkey():
    # DSA
    q = number.getPrime(128)

    while True:
        t = random.getrandbits(1024-128-1)
        p = (t * 2*q + 1)
        if number.isPrime(p):
            break

    e = (p-1) // q
    g = pow(2, e, p)

    x = random.randint(1, q-1)
    y = pow(g, x, p)

    return {'y':y, 'g':g, 'p':p, 'q':q, 'x':x}

def sign(m, key):
    g, p, q, x = key['g'], key['p'], key['q'], key['x']

    k = random.randint(1, q-1)
    print(f"k.bit_length() == {k.bit_length()}")

    Hm = int.from_bytes(sha256(m.encode()).digest(), 'big')

    r = pow(g, k, p) % q
    s = (number.inverse(k, q) * (Hm + x*r)) % q
    return (r, s)

def verify(m, sig, key):
    r, s = sig
    y, g, p, q = key['y'], key['g'], key['p'], key['q']
    if not (0 < r < q) or not (0 < s < q):
        return False

    Hm = int.from_bytes(sha256(m.encode()).digest(), 'big')
    w = number.inverse(s, q)
    u1 = (w * Hm) % q
    u2 = (w * r) % q
    v = ( (pow(g, u1, p) * pow(y, u2, p)) % p ) % q

    return v == r

def _is_valid_name(name):
    if not (0 < len(name) <= 20):
        print("Invalid username length!")
        return False

    for c in name:
        if c not in ascii_letters + digits:
            print("Invalid character in username!")
            return False

    if name == "admin":
        print("Username can't be 'admin'")
        return False

    return True

def sign_up(key):
    name = input("Please input your username: ")
    if not _is_valid_name(name):
        return

    (r, s) = sign(name, key)
    sig = name.encode() + r.to_bytes(20, 'big') + s.to_bytes(20, 'big')
    print(f"Here is your signature in hex: {sig.hex().upper()}")


def sign_in(key):
    data = input("Please send me your signature: ")
    try:
        data = bytes.fromhex(data)
    except ValueError:
        print("Invalid signature format!")
        return
    if not (40 < len(data) <= 60):
        print("Invalid signature length!")
        return

    (name, r, s) = (data[:-40].decode(), data[-40:-20], data[-20:])
    sig = map(lambda x: int.from_bytes(x, 'big'), (r, s))

    if not verify(name, sig, key):
        print("Wrong signature!")
        return

    print(f"Welcome, {name}")
    if name == "admin":
        print(f"The flag is {FLAG}")



menu = '''
1. sign up
2. sign in
3. exit\
'''

def main():
    try:
        if not proof_of_work():
            return

        print("Generating DSA parameters...")
        key = genkey()
        print(f"p = {key['p']}")
        print(f"q = {key['q']}")
        print(f"g = {key['g']}")
        print(f"y = {key['y']}")

        while True:
            print(menu)
            choice = input("$ ")

            if choice == "1":
                sign_up(key)

            elif choice == "2":
                sign_in(key)

            elif choice == "3":
                print("Bye!")
                return

            else:
                print("Invalid choice!")
                continue
    except:
        pass

main()