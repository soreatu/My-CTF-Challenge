# !/usr/bin/env sage
import random
import multiprocessing as mp

from json import load
from functools import partial


def check(sol, A, s):
    """Check whether *sol* is a solution to the subset-sum problem."""
    return sum(x*a for x, a in zip(sol, A)) == s


def solve(A, n, k, s, r, ID=None, BS=22):
    N = ceil(sqrt(n)) # parameter used in the construction of lattice
    rand = random.Random(x=ID) # seed

    indexes = set(range(n))
    small_vec = None
    
    itr = 0
    total_time = 0.0
    while True:
        # 1. initalization
        t0 = cputime()
        itr += 1
        # print(f"[{ID}] n={n} Start... {itr}")

        # 2. Zero Force
        kick_out = set(sample(range(n), r))
        # (k+1) * (k+2)
        # 1 0 ... 0 a0*N   N
        # 0 1 ... 0 a1*N   N
        # . . ... . ...    .
        # 0 0 ... 1 a_k*N N
        # 0 0 ... 0 s*N    k*N
        new_set = [A[i] for i in indexes - kick_out]
        lat = []
        for i,a in enumerate(new_set):
            lat.append([1*(j==i) for j in range(n-r)] + [N*a] + [N])
        lat.append([0]*(n-r) + [N*s] + [k*N])

        # 3. Randomly shuffle
        shuffle(lat, random=rand.random)

        # 4. BKZ!!!
        m = matrix(ZZ, lat)
        t_BKZ = cputime()
        m_BKZ = m.BKZ(block_size=BS)
        print(f"[{ID}] n={n} {itr} runs. BKZ running time: {cputime(t_BKZ):.3f}s")

        # 5. Check the result
        # print(f"[{ID}] n={n} first vector norm: {m_BKZ[0].norm().n(digits=4)}")
        for i, row in enumerate(m_BKZ):
            if check(row, new_set, s) and row.norm()^2 < 300:
                if small_vec == None:
                    small_vec = row
                elif small_vec.norm() > row.norm():
                    small_vec = row
                    print(f"[{ID}] n={n} Good", i, row.norm()^2, row, kick_out)
                    if row.norm()^2 == k:
                        print(f"[{ID}] n={n} After {itr} runs. FIND SVP!!!\n"
                              f"[{ID}] n={n} Single core time used: {total_time}s")
                        return True

        # 6. log average time per iteration
        itr_time = cputime(t0)
        total_time += itr_time
        # average_time = float(total_time / itr)
        # print(f"[{ID}] n={n} average time per itr: {average_time:.3f}s")



def main():
    CPU_CORE_NUM = 32

    k, n, d = 160, 180, 0.8
    s, A = load(open("data", "r"))
    r = 40 # ZERO FORCE

    new_k = n - k
    new_s = sum(A) - s
    solve_n = partial(solve, A, n, new_k, new_s, r)
    with mp.Pool(CPU_CORE_NUM) as pool:
        reslist = pool.imap_unordered(solve_n, range(200, 200+CPU_CORE_NUM))
        
        # terminate all processes once one process returns
        for res in reslist:
            if res:
                pool.terminate()
                break


if __name__ == "__main__":
    main()
