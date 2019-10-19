This was a pwn challenge at HITCON19 Qualifiers called Trick or Treat.

The challenge is a pretty simply binary that consists of a single main function.

```
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+4h] [rbp-2Ch]
  FakeStruct var2; // [rsp+8h] [rbp-28h]
  _QWORD *buffer; // [rsp+20h] [rbp-10h]
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  *(_OWORD *)&var2.bufSize = 0uLL;
  var2.value = 0LL;
  buffer = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  write(1, "Size:", 5uLL);
  __isoc99_scanf("%lu", &var2);
  buffer = malloc(var2.bufSize);
  if ( buffer )
  {
    printf("Magic:%p\n", buffer);
    for ( i = 0; i <= 1; ++i )
    {
      write(1, "Offset & Value:", 0x10uLL);
      __isoc99_scanf("%lx %lx", &var2.offset, &var2.value);
      buffer[var2.offset] = var2.value;
    }
  }
  _exit(0);
}
```

As we can see, all it does is it allocates a buffer of requested size, and then
in a loop it twice reads in an offset and a value and writes the value to the given
offset. Of course, the offset is not checked at all, so it looks like we can do 2
arbitrary OOB writes plus we get the address of a buffer allocated with malloc as a bonus.


So, how do we get code execution out of this?

First, clearly, we will need the address of libc. But how can we get that from a heap address?
In the normal case, there won't be any corralation between their ASLR bits. However, the allocation
size is arbitrary. How can we exploit that?

Now, what we can use is that if we exceed ptmalloc's MMAP_THRESHOLD, we are going
to get the allocation served by mmap. And if the size is large enough that the system
can not fit the required number of consecutive pages anywhere inbetween the gaps that
will exist starting from the mapping of libc to the end of the mapping of ld.so, vdso,
etc - then it will grow the mapping area simply downwards, with no gap, much less a
randomized gap inbetween.

In other words, with a large enough allocation, our chunk will be right next to the start
of libc, which means that we get the address of libc AND can write into it.

So, the challenge is, where do we write? We explored a lot of options.

First of all it's worth realizing that we actually only have 1 write. Although
on paper we have 2, the program won't do anything but exit with a syscall after
the second one. The only way this wouldn't be true is if we managed to overwrite
the stack-stored for loop count variable directly, but this isn't viable with
a single write.

So, we have to find the way to either solve the challenge with a single write,
or to extend our corruption abilities.

At this point we can note that the official solution uses a single write, abusing
`register_printf_function`, but, we weren't aware of this and we didn't read scanf
source carefully enough to find it, so we had to do it the hard way.

If you are interested in the PROPER solution, and it really is worth checking out
because by the looks of it this is a single write in libc that might come in quite
handy on other occasions too, then check out Angelboy's github for the official solution!

First we looked at things like malloc/free_hook, since scanf will use malloc/free
under certain conditions. However, because we cannot change the format string of
scanf, we can not hit the path in scanf that leads directly to a dynamic allocation.

Next, we could directly target the vtable of IO_2_1_stdin, which will be invoked by scanf.
Specifically, because the read buffer of stdin is at first empty, the IO_UNDERFLOW function
pointer from the vtable will be invoked. However, there are several issues with this:
1 The first scanf (that happens before our first OOB write) actually will fill the read buffer
(actually this can be gamed if we use just the right amount of spaces for example)
2 The bigger problem is the vtable protections introduced into libc-2.27. Since we can not point
the vtable anywhere AND we cannot use the wops trick anymore to chain the execution either, we
are out of luck with a single write. Of course, we could actually overwrite further values in ld.so
and that way defeat the check, but, since we only have a single write, that won't work.

So, again, we decided that this is not the way we want to go.

Instead we looked specifically at the conditions to trigger IO_UNDERFLOW in scanf. This path is
very useful to us, because this is when `IO_2_1_stdin` will actually do a read system call to
read into the memory pointed to by `_IO_buf_base`, with the amount of bytes read being
`_IO_buf_end` - `_IO_buf_base`. By default, `_IO_buf_base` points to another field of `IO_2_1_stdin`
(`_shortbuf`) and `_IO_buf_end` to the end of it. And whenever IO_UNDERFLOW is triggered, the read
happens and then `_IO_read_buf` and `_IO_read_end` are adjusted to signal that we have bytes
available in the buffer. From this point on, any time there's a read attempt on `IO_2_1_stdin`,
it won't actually trigger IO_UNDERFLOW, as long as there's bytes left in
the read buffer. Here are the relevant snippets from libc:

```
https://code.woboq.org/userspace/glibc/libio/fileops.c.html#489

  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

    (…)

  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
                       fp->_IO_buf_end - fp->_IO_buf_base);
```

This is invoked in `vscanf` via `inchar()` for every character that is read from the input,
and that is actually the `_IO_getc_unlocked` macro (`__uflow` resolves to IO_UNDERFLOW function
of stdin in this case):

```
https://code.woboq.org/userspace/glibc/stdio-common/vfscanf-internal.c.html#83
glibc/libio/bits/libio.h <this file is removed post libc-2.27 !!>

#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
        ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

So, we have two options. We could modify eithe `_IO_buf_base` and overwrite memory in front of
`IO_2_1_stdin` all the way to the end of `_shortbuf` or we could modify `_IO_buf_end` and overwrite
memory further after `_shortbuf`. The later seems compelling since this is where the vtable is, but
we already saw that this is not good enough on its own.

However, we can target the former instead! This will give us to really good things:
1 We can actually directly corrupt the GOT of libc, amazingly. And guess what, there are several functions
in it that get invoked when, yep, the vtable verification check of IO_UNDERFLOW aborts.
2 If we overwrite from before the `_IO_2_1_stdin` struct, we can overwrite all of that struct too, which
means overwriting both `_IO_read_ptr` and `_IO_read_end`. And if we can corrupt those, then we can bypass this
check in `_IO_getc_unlocked` and force an IO_UNDERFLOW:

```
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
        ? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```

(Also keep in mind that the `IO_read_ptr` value must be actually valid and point to memory that is not a 0,
plus the `_flag` field ot `IO_2_1_stdin` must be restored to a legit value.)

That is fantastic because that will mean that scanf will again come back to IO_UNDERFLOW, meanwhile we were
able to re-corrupt `_IO_buf_base` but also this time write into `_IO_buf_end`. So what do we do on the second
turn? Well, NOW we can target the `vtable` field itself. All we need to do is to corrupt it and then trigger
yet another scanf invoked IO_UNDERFLOW. So we once again will overwrite all of `IO_2_1_stdin` but this time
also corrupt the vtable and set the `_IO_read_ptr` and `_IO_read_end` so that `_IO_getc_unlocked` triggers
the underflow a third time.

And, as they say, third time is the charm, because this time we get an abort that results in a corrupted
GOT jmp which results in RIP control.

So, what now? Well, now you would normally jump to a one_gadget and be done with it.

Unfortunately, in practice we got quite unlucky and the one_gadget conditions just wouldn't work out at first.
So here we spent a loooooooot of time. However, we were (wrongly) convinced that this is the intended solution
path, so we kept digging. Because the stack looked _almost_ good (we hade a 0 at one qword less than the right
offset), we tried many different gadget chaining tricks, but nothing quite worked out. Then we also tried different
GOT members, because as it turns out we overwrite more than one. Luckily, we finally hit the lottery and got it
to work just right.

When all goes well, you run the exploit in the git and end up with something like this:

```
$ python trick_exp.py 
[+] Opening connection to 3.112.41.140 on port 56746: Done
Magic:
malloced ptr: 0x00007ff9a2f3d010
We want to execute: 0x00007ff9a3b53322
libc_base: 0x00007ff9a3b04000
stdin: 0x00007ff9a3eefa00
buf_base: 0x00007ff9a3eefa38
libc_got_target = 0x00007ff9a3eef048
waiting again...

first overflow_size: 0x00000a3c
desired flag2: 0x00007ff9a3b53322
[*] Switching to interactive mode
\x00Offset & Value:\x00
$ whoami
trick_or_treat
$ cat /home/trick_or_treat/flag
hitcon{T1is_i5_th3_c4ndy_for_yoU}
$ exit
[*] Got EOF while reading in interactive
```