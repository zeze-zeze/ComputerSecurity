from pwn import *

r = remote('140.113.207.233', 8822)
r.sendline(str(1804289383 ^ 0xdeadbeaf))
print(r.recvall(1))
