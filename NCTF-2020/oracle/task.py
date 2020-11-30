from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long
from secret import flag


m = bytes_to_long(flag)

while True:
    p = getPrime(512)
    q = getPrime(512)
    n = p * q
    e = getPrime(32)
    if GCD((p-1)*(q-1), e) == 1:
        d = inverse(e, (p-1)*(q-1))
        break

print(e, n, pow(m, e, n), sep='\n')


for _ in range(10000):
    cc = int(input("> "))
    mm = int.to_bytes(pow(cc, d, n), 1024//8, 'big')
    print(mm.startswith(b"\x00"))