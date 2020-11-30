from random import choice
from hashlib import sha256
from string import ascii_letters, digits

from RSA import RSA
from secret import FLAG


MENU = """
1. encrypt
2. decrypt
3. newkey
4. encflag
5. exit"""

def proof_of_work():
    proof = ''.join([choice(ascii_letters+digits) for _ in range(20)])
    _hexdigest = sha256(proof.encode()).hexdigest()
    print(f"sha256(XXXX+{proof[4:]}) == {_hexdigest}")
    try:
        prefix = input("Give me XXXX: ")
    except:
        print("Error!")
        exit(-1)
    return sha256((prefix+proof[4:]).encode()).hexdigest() == _hexdigest

def task():
    CHANCE = 5
    RRRSA = RSA(1024)
    print(f"My public key: {RRRSA.e}, {RRRSA.N}")

    for _ in range(10):
        try:
            print(MENU)
            choice = input("Your choice: ")

            if choice == "1":
                m = int(input("Your message: "))
                c = RRRSA.encrypt(m)
                print(f"Your cipher: {c}")

            elif choice == "2":
                c = int(input("Your message: "))
                d = int(input("Your decryption exponent: "))
                m = RRRSA.decrypt(c, d)
                print(f"Your message: {m}")

            elif choice == "3":
                RRRSA.gen_ed(1024)
                print(f"My new public key: {RRRSA.e}, {RRRSA.N}")

            elif choice == "4":
                if CHANCE:
                    CHANCE -= 1
                    flag = int.from_bytes(FLAG, 'big')
                    encflag = RRRSA.encrypt(flag)
                    print(f"encflag: {encflag}")
                else:
                    print("Nope, only 5 chances to get encflag.")

            else:
                print("Bye!")
                exit(0)

        except Exception as e:
            print(e)
            print("Error!")
            exit(-1)


if __name__ == "__main__":
    if proof_of_work():
        task()