load("GGH.sage")
from sage.misc.prandom import randint
from secret import flag

n = 150

assert(len(flag) == 42)
m = [ord(ch) for ch in flag]
# pad
for _ in range(n-len(m)):
    m.append(randint(-128, 128))
m = vector(ZZ, m)


ggh = GGH(n)
e = ggh.encrypt(m)

with open('ciphertext.txt', 'w') as f:
    for num in e:
        f.write(str(num) + ' ')

with open('key.pub', 'w') as f:
    for vct in ggh.pubkey:
        for num in vct:
            f.write(str(num) + ' ')
        f.write('\n')