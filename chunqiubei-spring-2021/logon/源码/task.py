import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from secret import flag


db = {
    "Administrator": "5893e3f5e1c29dc7f11b7b8acf1f6bab0a1a807ff65b554b48fbfaf76e474d5a",
}


def Menu():
    print("\n1. login\n2. register\n3. exit")
    return int(input("> "))

def AuthenticationHandshake():
    client_challenge = bytes.fromhex(input("client challenge: ").strip())
    assert len(client_challenge) == 8

    user = input("username: ").strip()
    assert 6 < len(user) < 20
    if user not in db.keys():
        print(f"{user} not in database!\n".encode())
        return
    shared_secret = db[user].encode()

    server_challenge = os.urandom(8)
    print(f"server challenge: {server_challenge.hex()}")

    client_credential = bytes.fromhex(input("client credential: ").strip())
    session_key = HKDF(shared_secret, 16, client_challenge+server_challenge, SHA256)
    if ComputeCredential(session_key, client_challenge) == client_credential:
        print(f"Welcome {user}")
        if user == "Administrator":
            print(flag)
    else:
        print("Login failed!")

def Register():
    user = input("username: ").strip()
    assert 6 < len(user) < 20
    if user in db.keys():
        print(f"{user} already in database!\n".encode())
        return
    hashed_password = input("hashed_password: ").strip()
    assert len(hashed_password) == 64
    db[user] = hashed_password
    print("Register successfully!\n")

def ComputeCredential(session_key, challenge):
    stream = bytearray([0]*16) + bytearray(challenge)
    aes = AES.new(session_key, mode=AES.MODE_ECB)
    for i in range(8):
        stream[16+i] ^= aes.encrypt(stream[i:i+16])[0]
    return stream[-8:]

def main():
    for _ in range(0x1337):
        choice = Menu()
        if choice == 1:
            AuthenticationHandshake()
        elif choice == 2:
            Register()
        else:
            return

if __name__ == '__main__':
    main()