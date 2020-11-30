from Crypto.Util.number import getPrime, getRandomNBitInteger, GCD, inverse


lcm = lambda x, y: x*y // GCD(x,y)


class RSA():
    def __init__(self, bits):
        p = getPrime(bits//2)
        q = getPrime(bits//2)
        self.N = p * q
        self.lbd = lcm(p-1, q-1)
        self.gen_ed(bits)

    def gen_ed(self, bits):
        while True:
            d = getRandomNBitInteger(int(bits*0.4))
            if GCD(d, self.lbd) == 1:
                e = inverse(d, self.lbd)
                self.e, self.d = e, d
                break

    def encrypt(self, m):
        return pow(m, self.e, self.N)

    def decrypt(self, c, d):
        return pow(c, d, self.N)