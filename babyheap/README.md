# Babyheap 0ctf 2018 Quals

This was a classic heap metadata corruption exploitation challenge.

The challenge binary itself is a pretty straightforward wrapper for playing with heap management. Simply, we have commands to allocate, free, read, and write chunks. However, we are limited because we can only allocate maximum 88 sized chunks. The point of this, of course, is that we are forced to using chunks that all go on the fastbin when freed, due to size.

# Vulnerability

The vulnerability in the Update function was pretty straightforward to see:

```
__int64 __fastcall Update(heap_mgt_array_t *heap_addr)
{
  __int64 result; // rax
  signed int idx; // [rsp+18h] [rbp-8h]
  int update_size; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  idx = read_number();
  if ( idx >= 0 && idx <= 15 && heap_addr->heap_mgt[idx].is_used == 1 )
  {
    printf("Size: ");
    result = read_number();
    update_size = result;
    if ( (signed int)result > 0 )               // only allow positive new size
    {
      result = heap_addr->heap_mgt[idx].chunk_size + 1;
      if ( update_size <= (unsigned __int64)result )// only allow write that is <= then the size+1
                                                // 
                                                // so of course this is an OFF BY ONE
      {
        printf("Content: ");
        read_into((void *)heap_addr->heap_mgt[idx].chunk_addr, update_size);
        LODWORD(result) = printf("Chunk %d Updated\n", (unsigned int)idx);
      }
    }
  }
  else
  {
    LODWORD(result) = puts("Invalid Index");
  }
  return result;
}
```

# Exploit Primitive

So, of course, we can write 1 byte past a chunk. What does that allow us to target? Of course the LSB of the size field of the next chunk, if we get sizes right and we don't get aligned up by +8 bytes.

The target used libc 2.24, which meant that classic unsorted bin attack using the forgotten chunks technique was possible.

# Get a chunk on the unsorted bin

In order to make that work though, we had to get chunks unto the unsorted bin, I guess that was the added challenge here. As it turns out, this isn't terribly complicated. If we overwrite the size of the next chunk with the off-by-one to make it look like it is large enough for the unsorted bin, e.g. 0xA0 (+1 for `in_use` bit), then free that chunk, then we could get it onto the unsorted chunk.

There's one caveat: libc heap also has a sanity check that the neighboring chunk at chunk+size ALSO has a valid size, so we would have to modify the bytes at chunk+0xA0 to make it so. This of course just points inside the controllable portion of another chunk if we allocate several, so it is a condition that is easy to satisfy.

# Text-book forgotten chunks attack

From here, the steps are pretty text-book, as we have created the condition that we have allocated chunks that overlap with a bigger chunk freed unto the unsorted bin:


1 allocate the unsorted bin chunk so that we can read/write overlapping chunks, splitting off a remainder that remains in the unsorted bin

2 fix up the overlapped chunks (that get zero'd out due to the allocation because the challenge is using `calloc`)

3 free the overlapped chunks onto the fastbin, so that we can leak out the fastbin fd pointers to get a heap address leak and a libc address leak

4 overwrite the bk pointer of the remainder chunk sitting in the unsorted bin with the address of `_IO_list_all`. The attack we will execute from here is basically Angelboy's technique described [here](http://4ngelboy.blogspot.hu/2016/10/hitcon-ctf-qual-2016-house-of-orange.html), otherwise known as [house of orange](https://github.com/shellphish/how2heap/blob/master/house_of_orange.c), plus the additional trick using `_IO_wstr_finish`.

5 trigger an allocation to a size that is smaller than the overwritten

6 this will trigger the unsorted bin walk, which first overwrites `_IO_list_all` with the address of the unsorted bin

7 next it places the split off chunk into the `smallbin[4]` since we select its size thusly (why [4]? Because the difference from unsorted bin address `&smallbin[4]` is the same as the offset of the `_chain` field of the `FILE` structure. That size for 64-bit systems is 0x60+ btw).

8 next it iterates to the next unsorted bin chunk, and of course things blow up in our face since we didn't fix them and the heap decides to abort

9 the abort procedure reaches `_IO_flush_all_lockp`, which walks `_IO_list_all`

10 our exploit is crap, so it was not made 100% reliable, therefore the first iteration sometimes ruins things. We are lazy and were very sleep deprived at this point, due to the fact that we did NOT have any environment to run the provided libc in for a VERY long time, resuling in unnecessary headache, heartache, yelling at computer screens and annoying teammates. (Specifically: if the actual target is libc 2.24, do NOT try to put together an exploit with this technique on either 2.23 (e.g. Ubuntu 16.04) OR 2.26 (e.g. Ubuntu 17.10) libc. The former misses checks and many things will work differently; the later added a check against the unsorted bin attack.)

11 our crap exploit sometimes of course survives the first loop, and follows the `_chain` pointer that happens to be the address at smallbin[4] to our controlled chunk

12 from here, we "just" need to set a whole bunch of fields right so that conditions are satisfied and `_IO_OVERFLOW` decides to invoke the call from our fake vtable; see conditions [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/genops.c;hb=4d76d3e59d31aa690f148fc0c95cc0c581aed3e8#l701), specifically we want this to be true `fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base`

13 the vtable address check in libc.2.24 (see [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libioP.h;hb=4d76d3e59d31aa690f148fc0c95cc0c581aed3e8#l828)) is circumvented by using the `_IO_wstr_finish` technique. (Note: if you want to follow the libc src: `_IO_OVERFLOW` resolves to `JUMP1`, `JUMP1` resolves to `_IO_JUMPS_FUNC`, and that resolves to using `IO_validate_vtable`. See [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/libioP.h;hb=4d76d3e59d31aa690f148fc0c95cc0c581aed3e8#l107).

14 further conditions in `_IO_wstr_finish` are satisfied by chunk fields to get us to the actual arbitrary function call with controlled RDI. See conditions [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=libio/wstrops.c;hb=4d76d3e59d31aa690f148fc0c95cc0c581aed3e8#l359).

15 get RIP control with RDI controlled, call `system("/bin/sh")`, spend a bunch of time failing at realizing where the flag is, finally find flag, move on to almost finishing another pwn challenge in time but of course running out of time. As one does!

For more details on offsets etc see `expl_final.py`.

I apologize for not using any funny names in the exploit code, thusly depriving you, the reader, of further enjoyment.
