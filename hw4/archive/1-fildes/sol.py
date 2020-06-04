from pwn import *

r = remote('140.113.207.233', 8812)
#r = process('./fildes')
r.recvuntil('magic number')
r.send(str(0xdeadbeaf))
r.recvuntil('magic string')
r.sendline('YOUSHALLNOTPASS')
print(r.recvall(1))
