This was another pwn challenge at the HITCON19 Qualifiers.

It was actually the third part of a 3-part challenge. My awesome
teammates Hege and KT have written writeups for the reverse and
programming parts, find them here: [reverse](https://kt.gy/blog/2019/10/hitconctf-2019-quals-reverse-emojivm/) [ppc](https://github.com/sorgloomer/writeups/blob/master/writeups/2019-hitcon-quals/2019-hitcon-quals--emojiivm.md)

So, if you've read those, you already know that this challenge
implements a stack-based VM, where every instruction is an emoji.
That's just awesome. Extra shoutout to the challenge creator who found
a semantically meaningful emoji for every single instruction. Even the
NOP instruction is an emoji that is a Chinese character for something like
"air" (according to Google translate). How great is that?

Here's the rundown of the emoji instruction set:

```
NOP: 🈳
ADD: ➕
SUB: ➖
MUL: ❌
MOD: ❓ 
XOR: ❎
AND: 👫
IS_LESS: 💀
IS_EQ: 💯
JMP: 🚀
JMP_IF: 🈶
JMP_IF_FALSE: 🈚
PUSH_EMOJI: ⏬
POP: 🔝
LD: 📤
ST: 📥
NEW: 🆕
FREE: 🆓
READ: 📄
POP_OBJ: 📝
FLUSH: 🔡
POP_INT64: 🔢
EXIT: 🛑
```

```
0: 😀
1: 😁
2: 😂
3: 🤣
4: 😜
5: 😄
6: 😅
7: 😆
8: 😉
9: 😊
10: 😍
```

The numbers are obvious and so are most of the instructions.
As for `NEW/FREE/READ/POP_OBJ` they basically implement heap
functionality: we can allocate an "object" of any desired size,
and then we can either read data directly into it or we can use
the stack-based `LD/ST` to read/write single values at selected
offsets.

So, what is the vulnerability? Actually, it is fairly obvious if we
compare how the `POP/PUSH_EMOJI` instructions deal with the stack vs
all other instructions:


```
    curr_emoji = *(_DWORD *)std::__cxx11::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::operator[](
                              program,
                              program_counter);
    switch ( *(_DWORD *)get_vm_command_opcode_from_emoji((__int64)&g_emoji_opcodes_table_1, &curr_emoji) )
    {
(...)
      case 2:                                   // 
                                                // 
                                                // execcute_ADD
                                                // 
                                                // pop 2 from stack, add, push to stack
        v2 = vm_stack_pointer--;
        val = g_vm_stack[v2];
        v3 = vm_stack_pointer--;
        val2 = g_vm_stack[v3];
        g_vm_stack[++vm_stack_pointer] = val2 + val;
        ++program_counter;
        continue;
(...)
      case 13:                                  // 
                                                // 
                                                // execute PUSH EMOJI (exit if SP == 1024; otherwise increment, convert
						// next opcode with convert_opcode_data_with_emoji_tbl2_unk, write to stack)
        if ( vm_stack_pointer == 1024 )
        {
          v23 = std::operator<<<wchar_t,std::char_traits<wchar_t>>(&std::wcout, error_str_stack_overflow);
          std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(
            v23,
            &std::endl<wchar_t,std::char_traits<wchar_t>>);
          exit(1);
        }
        emoji_integer_value_ptr = (unsigned int *)std::__cxx11::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::operator[](
                                                    program,
                                                    program_counter + 1);

        val = (signed int)convert_smiley_to_number(*emoji_integer_value_ptr);
        g_vm_stack[++vm_stack_pointer] = val;
        program_counter += 2;
        continue;
(...)
      case 14:                                  // 
                                                // 
                                                // 
                                                // execute POP (exit if SP == -1, otherwise decrement; throwaway value)
        if ( vm_stack_pointer == -1 )
        {
          v25 = std::operator<<<wchar_t,std::char_traits<wchar_t>>(&std::wcout, &error_str_underflow);
          std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(
            v25,
            &std::endl<wchar_t,std::char_traits<wchar_t>>);
          exit(1);
        }
        --vm_stack_pointer;
        ++program_counter;
        continue;
(...)
      case 22:                                  // POP_INT64 (pop value from stack, write it out)
        v36 = vm_stack_pointer--;
        val = g_vm_stack[v36];
        execute_POP_INT64(val);                 // idx >> stdout
        ++program_counter;
        continue;
```

Clearly, while the push/pop commands check that the stack pointer is within bounds before incrementing or decrementing,
every other instruction does NOT verify the stack pointer at all! So, we can underflow the stack pointer, and that is
all we need to get a shell. How do we do it?

First, let see what lies in memory before the VM's stack:

```
.bss:000000000020E200             ; gptr_obj *gptr_array[10]
.bss:000000000020E200 ?? ?? ?? ??+gptr_array      dq 0Ah dup(?)           ; DATA XREF: execute_LD+36↑o
.bss:000000000020E200 ?? ?? ?? ??+                                        ; execute_LD+95↑o ...
.bss:000000000020E250 ?? ?? ?? ??+                dq ?
.bss:000000000020E258 ?? ?? ?? ??+                dq ?
.bss:000000000020E260             ; _QWORD g_vm_stack[1024]
.bss:000000000020E260 ?? ?? ?? ??+g_vm_stack      dq 400h dup(?) 
```

```
00000000 gptr_obj        struc ; (sizeof=0x10, mappedto_9)
00000000 len             dq ?
00000008 buf             dq ?
00000010 gptr_obj        ends
```

Well isn't that convenient. When we run off the stack, we find ourselves in an array of pointers that represents
the allocations we can do. And each allocation is actually an object with two members: a length field and a ptr
to the actual heap buffer where the READ emojiVM instruction would actually write the input:

```
void __fastcall execute_NEW(unsigned __int64 size)
{
  __int64 v1; // rax
  __int64 v2; // rax
  char found; // [rsp+13h] [rbp-Dh]
  signed int i; // [rsp+14h] [rbp-Ch]
  gptr_obj *obj; // [rsp+18h] [rbp-8h]

  if ( size > 1500 )
  {
    v1 = std::operator<<<wchar_t,std::char_traits<wchar_t>>(&std::wcout, "Invalid size ( too large ) : ");
    v2 = std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(v1, size);
    std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(v2, &std::endl<wchar_t,std::char_traits<wchar_t>>);
    exit(1);
  }
  obj = (gptr_obj *)operator new(0x10uLL);
  obj->len = size;
  obj->buf = operator new[](size + 1);
  memset((void *)obj->buf, 0, size + 1);
  found = 0;
  for ( i = 0; i <= 9; ++i )
  {
    if ( !gptr_array[i] )
    {
      gptr_array[i] = obj;
      found = 1;
      break;
    }
  }
  if ( found != 1 )
  {
    if ( obj->buf )
      operator delete[]((void *)obj->buf);
    operator delete(obj);
  }
}
```

```
ssize_t __fastcall execute_READ_TO_OBJ(int index)
{
  bool v1; // al
  __int64 v2; // rax

  v1 = (unsigned __int8)is_in_range(0, 10, index) ^ 1 || !gptr_array[index];
  if ( !v1 )
    return read(0, (void *)gptr_array[index]->buf, gptr_array[index]->len);
  v2 = std::operator<<<wchar_t,std::char_traits<wchar_t>>(&std::wcout, "Invalid gptr index");
  std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(v2, &std::endl<wchar_t,std::char_traits<wchar_t>>);
  exit(1);
  return read(0, (void *)gptr_array[index]->buf, gptr_array[index]->len);
}
```

There is one more emojiVM instruction that we'll use a lot, and that's `POP_INT64`. This is an instruction that makes
little sense, apart from being useful for exploiting the binary :) It does what it sounds like: pop a full 64-bit variable
from the stack to stdout.

The exploit will use three main building blocks:
1 If we move the stack down to the address of an existing allocation, we can use the INT64 POP to leak out the heap's address.
2 Similarly, if we use the emoji push instruction and some arithmetic, we can place an arbitrary number on top of one of these pointers.
3 If we allocate an object AFTER we craft such a fake number in place, we will get two adjacent numbers, one our selected number and
the other a valid object pointer. If we then use ADD with an illegal offset stack, we can magically create a fake object that will point
to a chosen part of the heap, specifically to INSIDE another `obj->buf`.

From this, we have essentially gained a classic heap primitive: overlapped pointers. Since one of those pointers is an `obj->buf`
that can be written directly with `READ` and read with `POP_OBJ` and the other pointer is interpreted as an object that contains
the `obj->buf` field that it writes TO, we can trivially get read-write-anywhere. From the heap (known already), we can leak libc
address and in libc we can overwrite the `free_hook` which we can trigger with a controlled `rdi` via the emoji free instruction in
order to get a shell.

See the exploit code for details! 
