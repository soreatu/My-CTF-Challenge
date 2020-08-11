from string import ascii_letters
from flag import flag


ctoi = lambda x: ascii_letters.index(x)
itoc = lambda x: ascii_letters[x]

key = flag.strip('NCTF{}')
len_key = len(key)

plaintext = open('plaintext.txt', 'r').read()

plain = ''.join(p for p in plaintext if p in ascii_letters)
cipher = ''.join( itoc( ( ctoi(p) + ctoi( key[i % len_key] ) ) % 52 )  for i,p in enumerate(plain) )

open('ciphertext.txt', 'w').write(cipher)