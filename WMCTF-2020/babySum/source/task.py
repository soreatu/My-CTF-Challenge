from json import dump
from random import SystemRandom

random = SystemRandom()

k, n, d = 20, 120, 0.8

B = 2**(n/d)
A = [random.randint(1, B) for _ in range(n)]
s = sum(A[index] for index in random.sample(range(n), k))

dump((s, A), open("data", "w"))