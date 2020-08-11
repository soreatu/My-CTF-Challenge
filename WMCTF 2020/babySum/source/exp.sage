import random
import multiprocessing as mp

from json import load
from functools import partial


def check(sol, A, s):
    """Check whether *sol* is a solution to the subset-sum problem."""
    return sum(x*a for x, a in zip(sol, A)) == s

def readData(filename):
    """Read data from the file and parse data to python object.

    Args:
        filename (str): name of the file to be read

    Returns:
        list: the parsed object
    """
    A = []
    with open(filename, "r") as f:
        data = f.read().strip()
    for a in data.split("  "):
        A.append(int(a.split("=")[1]))
    return A


def solve(A, n, k, s, ID=None, BS=22):
    N = ceil(sqrt(n)) # parameter used in the construction of lattice
    rand = random.Random(x=ID) # seed

    ############################
    # 1. Construct the lattice #
    ############################
    #  (n+1) * (n+2)
    #  1 0 ... 0 a_0*N   N
    #  0 1 ... 0 a_1*N   N
    #  . . ... .  ...    .
    #  0 0 ... 1 a_n*N   N
    #  0 0 ... 0  s*N   k*N
    lat = []
    for i, a in enumerate(A):
        lat.append([1*(j == i) for j in range(n)] + [N*a] + [N])
    lat.append([0]*n + [N*s] + [k*N])

    # main loop
    itr = 0
    start_time = cputime()
    while True:
        itr += 1
        # print(f"[{ID}] {itr} runs.")

        #######################
        # 2. Randomly shuffle #
        #######################
        l = lat[::]
        shuffle(l, random=rand.random)

        #############
        # 3. BKZ!!! #
        #############
        m = matrix(ZZ, l)
        t_BKZ = cputime()
        m_BKZ = m.BKZ(block_size=BS)
        print(f"[{ID}] n={n} {itr} runs. BKZ running time: {cputime(t_BKZ):.3f}s")

        #######################
        # 4. Check the result #
        #######################
        for i, row in enumerate(m_BKZ):
            if check(row, A, s):
                if row.norm()^2 == k:
                    print(f"[{ID}] n={n} After {itr} runs. FIND SVP!!! {row}\n"
                          f"Single core time used: {cputime(start_time):.3f}s")
                    return True

def main():
    CPU_CORE_NUM = 4
    k, n = 20, 120
    s, A = load(open("data", "r"))
    solve_n = partial(solve, A, n, k, s)
    with mp.Pool(CPU_CORE_NUM) as pool:
        reslist = pool.imap_unordered(solve_n, range(CPU_CORE_NUM))

        # terminate all processes once one process returns
        for res in reslist:
            if res:
                pool.terminate()
                break

if __name__ == "__main__":
    main()