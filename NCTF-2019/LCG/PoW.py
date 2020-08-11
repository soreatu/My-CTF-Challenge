#!/usr/bin/env python3
import sys
import hashlib

'''
This script is for proof of work.

Example:
    $ python PoW.py e53156e1d40a73 060dd9e3e90ede69de1ca97c33c69eab2b3e1f4132aa3a3307ea650b6b30a569
    e53156e1d40a73456acb

Note:
    Plz be patient since it may take several seconds to calculate the correct sha256 digest.
'''

prefix = bytes.fromhex(sys.argv[1])
digest = sys.argv[2]

for i in range(256**3):
    guess = prefix + i.to_bytes(3, 'big')
    if hashlib.sha256(guess).hexdigest() == digest:
        print('Find: ' + guess.hex())
        break
else:
    print('Not found...')