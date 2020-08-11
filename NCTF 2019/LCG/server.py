import os
import hashlib
from string import ascii_letters
from Crypto.Util.number import *
from Crypto.Random.random import randrange, getrandbits, choice

from flag import flag

banner = '''
 __      __   _                    _         _   _          _    ___ ___                  _    _ 
 \ \    / /__| |__ ___ _ __  ___  | |_ ___  | |_| |_  ___  | |  / __/ __| __ __ _____ _ _| |__| |
  \ \/\/ / -_) / _/ _ \ '  \/ -_) |  _/ _ \ |  _| ' \/ -_) | |_| (_| (_ | \ V  V / _ \ '_| / _` |
   \_/\_/\___|_\__\___/_|_|_\___|  \__\___/  \__|_||_\___| |____\___\___|  \_/\_/\___/_| |_\__,_|
                                                                                                 '''

def proof_of_work():
    s = os.urandom(10)
    hash_digest = hashlib.sha256(s).hexdigest()

    print '[++++++++++++++++] proof of work [++++++++++++++++]'
    print '[+] s = os.urandom(10)'
    print '[+] hashlib.sha256(s).hexdigest() = ' + hash_digest
    print "[+] s[:7].encode('hex') = " + s[:7].encode('hex') 
    # print s.hex()
    # print s.encode('hex')
    
    try:
        ss = raw_input("[-] s.encode('hex') = ").decode('hex')
    except:
        print('[+] Invalid string, exit...')
        exit(0)

    if hashlib.sha256(ss).hexdigest() != hash_digest:
        print('[+] Wrong string, exit...')
        exit(0)


    print '[++++++++++++++++] Proof completed [++++++++++++++++]'

    # print '\n[++++++++++++++++]  [++++++++++++++++]'
    print '''\nclass LCG(object):
    def __init__(self, seed):
        self.N = getPrime(256)
        self.a = randrange(self.N)
        self.b = randrange(self.N)
        self.seed = seed % self.N
        self.state = self.seed

    def next(self):
        self.state = (self.a * self.state + self.b) % self.N
        return self.state
[++++++++++++++++] Have fun [++++++++++++++++]
'''

class LCG(object):
    def __init__(self, seed):
        self.N = getPrime(256)
        self.a = randrange(self.N)
        self.b = randrange(self.N)
        self.seed = seed % self.N
        self.state = self.seed

    def next(self):
        self.state = (self.a * self.state + self.b) % self.N
        return self.state

def challenge1():
    print '[++++++++++++++++] Generating challenge 1 [++++++++++++++++]'
    init_seed = getrandbits(256)
    lcg = LCG(init_seed)
    print '[+] init_seed = getrandbits(256)'
    print '[+] lcg = LCG(init_seed)'
    print '[+] lcg.N = ' + str(lcg.N)
    print '[+] lcg.a = ' + str(lcg.a)
    print '[+] lcg.b = ' + str(lcg.b)
    print '[+] lcg.next() = ' + str(lcg.next())
    # print lcg.seed
    guess = int(raw_input("[-] lcg.seed = "))
    if guess != lcg.seed:
        print '[!] Sorry, you are wrong, exit...'
        exit(0)
    print '[++++++++++++++++] Challenge 1 completed [++++++++++++++++]\n\n'

def challenge2():
    print '[++++++++++++++++] Generating challenge 2 [++++++++++++++++]'
    init_seed = getrandbits(256)
    lcg = LCG(init_seed)
    print '[+] init_seed = getrandbits(256)'
    print '[+] lcg = LCG(init_seed)'
    print '[+] lcg.N = ' + str(lcg.N)
    print '[+] lcg.a = ' + str(lcg.a)
    print '[+] lcg.next() = ' + str(lcg.next())
    print '[+] lcg.next() = ' + str(lcg.next())
    # print lcg.seed
    guess = int(raw_input("[-] lcg.seed = "))
    if guess != lcg.seed:
        print '[!] Sorry, you are wrong, exit...'
        exit(0)
    print '[++++++++++++++++] Challenge 2 completed [++++++++++++++++]\n'

def challenge3():
    print '[++++++++++++++++] Generating challenge 3 [++++++++++++++++]'
    init_seed = getrandbits(256)
    lcg = LCG(init_seed)
    print '[+] init_seed = getrandbits(256)'
    print '[+] lcg = LCG(init_seed)'
    print '[+] lcg.N = ' + str(lcg.N)
    print '[+] lcg.next() = ' + str(lcg.next())
    print '[+] lcg.next() = ' + str(lcg.next())
    print '[+] lcg.next() = ' + str(lcg.next())
    # print lcg.seed
    guess = int(raw_input("[-] lcg.seed = "))
    if guess != lcg.seed:
        print '[!] Sorry, you are wrong, exit...'
        exit(0)
    print '[++++++++++++++++] Challenge 3 completed [++++++++++++++++]\n'

def challenge4():
    print '[++++++++++++++++] Generating challenge 4 [++++++++++++++++]'
    init_seed = getrandbits(256)
    lcg = LCG(init_seed)
    print '[+] init_seed = getrandbits(256)'
    print '[+] lcg = LCG(init_seed)'
    for _ in range(6):
        print '[+] lcg.next() = ' + str(lcg.next())
    # print lcg.seed
    guess = int(raw_input("[-] lcg.seed = "))
    if guess != lcg.seed:
        print '[!] Sorry, you are wrong, exit...'
        exit(0)
    print '[++++++++++++++++] challenge 4 completed [++++++++++++++++]\n'
    print '[+] Good job! Here is your flag: ' + flag



def main():
    challenge1()
    challenge2()
    challenge3()
    challenge4()


if __name__ == '__main__':
    print banner
    proof_of_work()
    try:
        main()
    except:
        print '[+] Bye!'
        exit(0)