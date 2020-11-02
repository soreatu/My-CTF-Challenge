# BabyProof
## Zero-knowledge proof

Zero-knowledge proof is a hot topic in the field of Cryptography, and has many applications in Blockchain. There are, however, few CTF chanlleges on this topic. So, I made this challenge for fun, though the key point to solve the challenge has no relation with zero-knowledge proof.

Actually, the construction of the challenge is similar to that of the [Schnorr Signature Scheme](https://quirks.ed25519.info/), which uses a technique, known as [Fiat–Shamir heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic), to convert an interactive proof of knowledge into a non-interactive one by applying a cryptographic hash function as the random oracle.

![image-20201019214230930](https://i.loli.net/2020/11/02/xL6bHzMdRrfeUPZ.png)

The signature scheme works in that the randomly (uniformly) selected scalar `r` **masks** the multiplication of `h` and `a` over the prime-order group. Therefore, the verifier acquires **zero** knowledge about the secret key `a`, while can be convinced that the prover really knows `a`.

## HNP

However, in this task, we can see that the distribution of the secret selected scalar $v$ over the prime-order group $\mathbb{Z}_q^*$ is not uniform:

```python
v = getRandomRange(1, x)
```

It always falls in the interval $[1, x]$, where $x$ is a 247-bit integer and the prime $q$ is about 256-bit, thus making $v$ relatively small compared to $q$. And this leads to a well-known problem in Cryptanalysis -- **the hidden number problem**.

From the instance, we can continuously get some data that satisfying
$$
r_i = v_i - c_i\cdot x \pmod {q_i},
$$
where only $v_i$ and $x$ are unknown.

By some transformation, it can be rewritten as
$$
v_i =   - k_i q_i + c_i x + r_i.
$$
Then, we can construct the lattice
$$
L = 
\begin{bmatrix}
q_1 &     &        &     &   &    & \\
    & q_2 &        &     &   &    & \\
   	&     & \ddots &     &   &    & \\
    &     &        & q_n &   &    & \\
c_1 & c_2 & \cdots & c_n & 1 &    & \\
r_1 & r_2 & \cdots & r_n &   & 2^{248}\\
\end{bmatrix}
$$
It is easy to show that the linear combination $[-k_1, -k_2, \cdots, -k_n, x, 1]$ of the lattice basis can result in a quite short lattice point $[v_1, v_2, \cdots, v_n, x, 2^{248}]$. By applying lattice reduction algorithm such as LLL to $L$, we can easily find this short lattice point, from which $x$ is recovered.

## Code

The script to gather sufficient data (stored in the file `data`):

```python
import json
from hashlib import sha256
from string import ascii_letters, digits

from pwn import *
from pwnlib.util.iters import bruteforce


def proof_of_work(r):
    r.recvuntil(b"XXXX+")
    suffix = r.recv(16).decode()
    r.recvuntil(b"== ")
    _hexdigest = r.recvline().strip().decode()
    print(f"suffix: {suffix}\nhexdigest: {_hexdigest}")

    prefix = bruteforce(
        lambda x: sha256((x+suffix).encode()).hexdigest() == _hexdigest,
        ascii_letters + digits,
        4,
        "fixed"
    )
    print(prefix)
    r.sendline(prefix)

def main():
    # Get data
    qs = []
    cs = []
    rs = []

    for i in range(50):
        print(i)
        conn = remote("101.32.203.233", 23333)
        # context.log_level = "debug"

        proof_of_work(conn)

        conn.recvline_endswith(b"I really have knowledge of x.")

        g, y, _, q, t, r = conn.recvall().decode().strip().split("\n")[-6:]
        gyt = b"".join(
            map(
                lambda x: int.to_bytes(len(str(x)), 4, 'big') + str(x).encode(),
                (g, y, t)
            ))
        c = int.from_bytes(sha256(gyt).digest(), 'big')

        qs.append(int(q))
        cs.append(int(c))
        rs.append(int(r))
        print(q, c, r)

        conn.close()

    json.dump([qs, cs, rs], open("data", "w"))

if __name__ == "__main__":
    main()
```

And the script to solve the HNP:

```python
# SageMath 9.1
import json
from Crypto.Util.number import long_to_bytes

qs, cs, rs = json.load(open("data", "r"))

# HNP
N = 50
M = matrix(ZZ, N+2, N+2)

# q1
#    q2
#       ...
#           qn
# c1 c2 ... cn  1
# r1 r2 ... rn    2^248
for i in range(N):
    M[i,i]  = qs[i] # qi
    M[-2,i] = cs[i] # ci
    M[-1,i] = rs[i] # ri
M[-2,-2] = 1
M[-1,-1] = 2^248

M_lll = M.LLL()

x = M_lll[0,-2]

print(long_to_bytes(x))
# b'n1ctf{S0me_kn0wl3dg3_is_leak3d}'
```