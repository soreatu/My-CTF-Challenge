from json import load

k, n, d = 20, 120, 0.8
s, A = load(open("data", "r"))

while True:
    inp = input("Please input the solution (seperated by comma): ") # <- 0, 1, 0, 1, ...
    sol = [int(i) for i in inp.split(',')]

    assert len(sol) == n
    assert all(i == 0 or i == 1 for i in sol)
    assert sum(i == 1 for i in sol) == k
    if sum(x*a for x, a in zip(sol, A)) == s:
        m = int(''.join(str(i) for i in  sol), 2)
        print(f"TQL! flag is {str(m).join(['WMCTF{', '}'])}")
        break