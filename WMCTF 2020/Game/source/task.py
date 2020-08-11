# !/usr/bin/env python3
import socketserver
import os, sys, signal
import string, random
from hashlib import sha256

from Crypto.Cipher import AES

from secret import flag

BANNER = br"""
      ___           ___           ___                         ___
     /\  \         /\  \         /\__\                       /\__\
    _\:\  \       |::\  \       /:/  /          ___         /:/ _/_
   /\ \:\  \      |:|:\  \     /:/  /          /\__\       /:/ /\__\
  _\:\ \:\  \   __|:|\:\  \   /:/  /  ___     /:/  /      /:/ /:/  /
 /\ \:\ \:\__\ /::::|_\:\__\ /:/__/  /\__\   /:/__/      /:/_/:/  /
 \:\ \:\/:/  / \:\~~\  \/__/ \:\  \ /:/  /  /::\  \      \:\/:/  /
  \:\ \::/  /   \:\  \        \:\  /:/  /  /:/\:\  \      \::/__/
   \:\/:/  /     \:\  \        \:\/:/  /   \/__\:\  \      \:\  \
    \::/  /       \:\__\        \::/  /         \:\__\      \:\__\
     \/__/         \/__/         \/__/           \/__/       \/__/
"""
MENU = br"""
1. encrypt
2. guess
3. exit
"""

class Task(socketserver.BaseRequestHandler):
    def _recvall(self):
        BUFF_SIZE = 2048
        data = b''
        while True:
            part = self.request.recv(BUFF_SIZE)
            data += part
            if len(part) < BUFF_SIZE:
                break
        return data.strip()

    def send(self, msg, newline=True):
        try:
            if newline:
                msg += b'\n'
            self.request.sendall(msg)
        except:
            pass

    def recv(self, prompt=b'> '):
        self.send(prompt, newline=False)
        return self._recvall()

    def recvhex(self, prompt=b'> '):
        self.send(prompt, newline=False)
        try:
            data = bytes.fromhex(self._recvall().decode('latin-1'))
        except ValueError as e:
            self.send(b"Wrong hex value!")
            self.close()
            return None
        return data

    def close(self):
        self.send(b"Bye~")
        self.request.close()

    def pad(self, data):
        pad_len = 16 - len(data)%16
        return data + bytes([pad_len])*pad_len

    def proof_of_work(self):
        random.seed(os.urandom(8))
        proof = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])
        _hexdigest = sha256(proof.encode()).hexdigest()
        self.send(f"sha256(XXXX+{proof[4:]}) == {_hexdigest}".encode())
        x = self.recv(prompt=b'Give me XXXX: ')
        if len(x) != 4 or sha256(x+proof[4:].encode()).hexdigest() != _hexdigest:
            return False
        return True

    def handle(self):
        signal.alarm(1200)

        self.send(BANNER)
        if not self.proof_of_work():
            return

        secret = os.urandom(48)
        key = os.urandom(16)
        IV = os.urandom(16)
        aes = AES.new(key, mode=AES.MODE_CBC, iv=IV)
        self.send(f"IV is: {IV.hex()}".encode())
        self.send(b"Guess the secret, and I will give you the flag if you're right~!")

        while True:
            self.send(MENU, newline=False)
            choice = self.recv()

            if choice == b"1":
                msg = self.recvhex(prompt=b"Your message (in hex): ")
                if not msg: break
                cipher = aes.encrypt(self.pad(msg + secret))
                self.send(cipher.hex().encode())
                continue
            elif choice == b"2":
                guess = self.recvhex(prompt=b"Your guess (in hex): ")
                if not guess: break
                if guess == secret:
                    self.send(b"TQL!!! Here is your flag: " + flag)
                else:
                    self.send(b"TCL!!!")

            self.close()
            break

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class ForkedServer(socketserver.ForkingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10000
    server = ForkedServer((HOST, PORT), Task)
    server.allow_reuse_address = True
    server.serve_forever()