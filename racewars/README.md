# racewards dc 2018 quals

This was an exploitation challenge with a classic ctf menu game. The game implemented a custom allocator on top of malloc and this is what we had to exploit.

The game itself is a car racing game. We can play in two phases, first we can assemble parts of our car and then we can modify our car once we have all parts (chassis, engine, tires, transmission) and then we can race the car. Really the racing was a nothing NOP, just a printf that we lost followed by everything allocated from the real libc heap freed and  exit. Also, the part assembly+modification had simpler logic then indicated by some menu items because in reality we could only do limited number of things. For example no matter what type chassis we pick, we always get the VW Jetta etc. The code also had a lot of unused but compiled in functions, structures with fields that were useless.. it was a little strange. Maybe it was all there as hints to think about the never used object field of the main arena.. but we didn't need that anyway (see the notes at the end).

# object types

The important structures for the game had the following fields:

```
00000000 arena           struc ; (sizeof=0x54, mappedto_6)
00000000 data_start      dq ?
00000008 data_end        dq ?
00000010 next            dq ?
00000018 iterated_cnt    dq ?
00000020 max_allocation_size dq ?
00000028 list_head       dq ?
00000030 field_30        dq ?
00000038 last_allocated_slot? dq ?               ; offset
00000040 never_initialized_obj dq ?              ; offset
00000048 nothing         dq ?
00000050 start_of_data   dd ?
00000054 arena           ends
00000054
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 slot_hdr        struc ; (sizeof=0x10, mappedto_7)
00000000 next_slot       dq ?
00000008 data_ptr        dq ?                    ; offset
00000010 slot_hdr        ends
00000010
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 ar_never_obj    struc ; (sizeof=0x18, mappedto_14)
00000000 fnptr           dq ?                    ; offset
00000008 data            dq ?                    ; offset
00000010 next            dq ?                    ; offset
00000018 ar_never_obj    ends
00000018
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 chass           struc ; (sizeof=0x18, mappedto_8)
00000000 field_0         db ?
00000001 field_1         db ?
00000002                 db ? ; undefined
00000003                 db ? ; undefined
00000004                 db ? ; undefined
00000005                 db ? ; undefined
00000006                 db ? ; undefined
00000007                 db ? ; undefined
00000008 self_ptr?       dq ?
00000010 name            db 8 dup(?)
00000018 chass           ends
00000018
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 engine_         struc ; (sizeof=0x18, mappedto_9)
00000000 whatev          db ?
00000001 is_broken_2     db ?
00000002 v115            db ?
00000003 zero            db ?
00000004 field_4         db ?
00000005 field_5         db ?
00000006 field_6         db ?
00000007 field_7         db ?
00000008 name            db 16 dup(?)
00000018 engine_         ends
00000018
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 transm          struc ; (sizeof=0x18, mappedto_10)
00000000 gear_cnt        dq ?
00000008 trans_type      db ?
00000009 gears           db 5 dup(?)
0000000E field_E         db ?
0000000F field_F         db ?
00000010 field_10        dq ?
00000018 transm          ends
00000018
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 car             struc ; (sizeof=0x38, mappedto_11)
00000000 chassis         dq ?                    ; offset
00000008 tires           dq 4 dup(?)
00000028 transmission    dq ?                    ; offset
00000030 engine          dq ?                    ; offset
00000038 car             ends
00000038
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 tire            struc ; (sizeof=0x20, mappedto_13)
00000000 width           dw ?
00000002 aspect          dw ?
00000004 thickness       dw ?
00000006 type            dw ?
00000008 field_8         dw ?
0000000A field_A         db ?
0000000B field_B         db ?
0000000C field_C         dq ?
00000014 field_14        dq ?
0000001C field_1C        dd ?
00000020 tire            ends
```

# custom allocator

The most important part of this challenge was the custom allocator used by it. My teammates reversed this, so I had the easy job left having to do the exploiting of the challenge with this knowledge, really.

The reversed functions speak for themselves, so I just copy in the pseudocode. At a glance:
* allocator uses arenas allocated directly from malloc, arena has control structure followed directly by its data where it allocates from
* arenas are fixed size, only main arena is allocated by default, if it filled up, a new one is created and so on
* arenas by default have a simply "bump allocator" behavior, just return the sequentially next data offset and increment used size. This works easily because there are never frees on this custom arena allocator ever.
* but, arenas only do this for allocation requests smaller than arena->max_allocation_size. If they ever get a larger one, the allocator will allocate from the heap a new slot descriptor, which simply has two fields, a next for a linked list and a pointer to the actual data which in this case is directly allocated with malloc.
* slots are ALSO never freed, only the data_ptr of them can be set to 0.
* so, whenever we have to make a too large allocation, we try to see if on the slot linked list there is an unused slot, if yes then we allocate from malloc and into that slot's data_ptr we place the result. If no, then we create a new slot.
* otherwise, if we have to make an allocation <= arena->max_allocation_size, then we simply attempt the bump allocation, but if we have run out of size, we go to the next arena. If in the end neither arena can satisfy the request, we allocate a new arena
* arenas are linked together in two ways. First, there is a next field that it used to go to the next arena when the current couldn't satisfy the request. But, there is also the list_head field, which actually only matters for the main_arena, because always main_arena->list_head decides which arena do we start allocation attemps at when we look for an arena that can satisfy a request. For mainting the list_head, the arenas also have a field that is iteration_cnt. This is incremented for every arena any time we have to make a NEW arena. Once the iterator count of an arena reached four, it becomes the new list_head. This is walked always from list_head. Basically this means in practice that at first we always start from the main arena, but once we have created four new arenas, we will start from the second arena, after 8 arenas we go the next one and soon.

```
void *__fastcall allocate(arena *main_arena, unsigned __int64 size)
{
  void *result; // rax

  if ( main_arena->max_allocation_size < size )
    result = alloc_and_find_or_create_slot(main_arena, size);// 
                                                // 
                                                // if size too large -> direct malloc done on the size
                                                // then put into last allocated slot.
                                                // 
                                                // that's good for us, we will have to do a LARGE LARGE tire
                                                // -> this sets last_allocated_slot
  else
    result = allocate_in_any_arena(main_arena, size, 1LL);
  return result;
}
```

```
slot_hdr *__fastcall alloc_and_find_or_create_slot(arena *main_arena, __int64 req_sz)
{
  __int64 v3; // rsi
  slot_hdr *result; // rax
  unsigned __int64 v5; // rax
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]
  slot_hdr *slot_it; // [rsp+20h] [rbp-10h]
  slot_hdr *slot; // [rsp+20h] [rbp-10h]
  slot_hdr *ptr; // [rsp+28h] [rbp-8h]

  v3 = main_arena->nothing;
  ptr = (slot_hdr *)malloc_(req_sz); 	//note: this is just a straight wrapper for malloc()
  if ( !ptr )
    return 0LL;
  v6 = 0LL;
  for ( slot_it = main_arena->last_allocated_slot_; slot_it; slot_it = (slot_hdr *)slot_it->next_slot )
  {
    if ( !slot_it->data_ptr )                   // if there is a slot that's empty, then assign it
    {
      slot_it->data_ptr = ptr;
      return ptr;
    }
    v5 = v6++;
    if ( v5 > 3 )
      break;
  }
  slot = (slot_hdr *)allocate_in_any_arena(main_arena, 0x10uLL, 1LL);// 
                                                // 
                                                // otherwise, make a new slot and assign to that
  if ( slot )
  {
    slot->data_ptr = ptr;
    slot->next_slot = (__int64)main_arena->last_allocated_slot_;
    main_arena->last_allocated_slot_ = slot;
    result = ptr;
  }
  else
  {
    free(ptr);
    result = 0LL;
  }
  return result;
}
```

```
void *__fastcall allocate_in_any_arena(arena *main_ar, unsigned __int64 req_sz, __int64 align)
{
  char *data; // [rsp+20h] [rbp-10h]
  arena *arena; // [rsp+28h] [rbp-8h]

  arena = (arena *)main_ar->list_head;
  do
  {
    data = (char *)arena->data_start;
    if ( align )
      data = (char *)((unsigned __int64)(data + 7) & 0xFFFFFFFFFFFFFFF8LL);
    if ( arena->data_end - (signed __int64)data >= req_sz )// 
                                                // if req_sz is zero, the
                                                // allocation succeeds without
                                                // modifying data_start.
    {
      arena->data_start = (__int64)&data[req_sz];
      return data;
    }
    arena = (arena *)arena->next;
  }
  while ( arena );                              // if not found, allocate new arena
  return allocate_from_new_secondary_arena(main_ar, req_sz);
}
```

```
void *__fastcall allocate_from_new_secondary_arena(arena *main_arena, __int64 size)
{
  unsigned __int64 curr_it_cnt; // rax
  arena *ar_it; // [rsp+10h] [rbp-20h]
  __int64 new_ar_size; // [rsp+18h] [rbp-18h]
  arena *new_ar; // [rsp+20h] [rbp-10h] MAPDST
  void *data_alloced; // [rsp+20h] [rbp-10h]

  new_ar_size = main_arena->data_end - (_QWORD)main_arena;
  new_ar = (arena *)memalign(0x10uLL, new_ar_size, main_arena->nothing);
  if ( !new_ar )
    return 0LL;
  new_ar->data_end = (__int64)new_ar + new_ar_size;
  new_ar->next = 0LL;
  new_ar->iterated_cnt = 0LL;
  data_alloced = (void *)(((unsigned __int64)&new_ar->max_allocation_size + 7) & 0xFFFFFFFFFFFFFFF8LL);// 
                                                // 
                                                // we automatically allocate the data and increment data_start thusly.
                                                // 
  new_ar->data_start = (__int64)data_alloced + size;
  for ( ar_it = (arena *)main_arena->list_head; ar_it->next; ar_it = (arena *)ar_it->next )
  {
    curr_it_cnt = ar_it->iterated_cnt;
    ar_it->iterated_cnt = curr_it_cnt + 1;      // iterated count: the point of this is that we can iterate an arena
                                                // at most 4 times, after this is it will go off the list_head, aka
                                                // it will never be iterated again.
                                                // 
                                                // meaning, it will not come up in allocate_in_any_arena() any longer.
    if ( curr_it_cnt > 4 )
      main_arena->list_head = ar_it->next;
  }
  ar_it->next = (__int64)new_ar;
  return data_alloced;
}
```

# vulnerabilities

There were two vulnerabilities required to solve this challenge or more like one vulnerability and one feature.

The main vulnerability was that there was an integer overflow in the size for tires that was allowed. This code really makes "no sense" as tires should be limited at 4 and the tire structure size in terms of what is useful is small than 32 anyway. Regardless, tires are allocated like this:

```
tire *__fastcall create_tire(arena *main_arena, _DWORD *tire_cnt_out)
{
  const char *v2; // rdi
  int tire_cnt; // [rsp+10h] [rbp-20h]
  int alloc_size; // [rsp+14h] [rbp-1Ch]
  tire *t; // [rsp+18h] [rbp-18h] MAPDST
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  *tire_cnt_out = 0;
  puts("how many pairs of tires do you need?");
  __isoc99_scanf("%d", &tire_cnt);
  if ( tire_cnt <= 1 )
  {
    puts("you need at least 4 tires to drive...");
    exit(1);
  }
  alloc_size = 32 * tire_cnt;
  t = (tire *)allocate(main_arena, 32 * tire_cnt);
  if ( t )
    *tire_cnt_out = 2 * tire_cnt;
  t->aspect = 'A';
  t->type = 'R';
  t->thickness = 15;
  t->field_A = 80;
  t->field_B = 0;
  t->field_8 = 0xFFFFu;
  puts("all you can afford is some basic tire...");
  puts("but they'll do!\n");
  if ( t->type == 'R' )
    v2 = "R";
  else
    v2 = (const char *)&unk_40209C;
  printf(
    "Your Tires are: %c%d%d%s%d\n",
    (unsigned int)t->field_A,
    (unsigned __int16)t->width,
    (unsigned __int16)t->aspect,
    v2,
    (unsigned __int16)t->thickness,
    tire_cnt_out);
  return t;
}
```

So if we set (2**32 >> 5) as the size, then we get a 0 sized allocation. Note that the tire was the only element where we had control over the size, all others (chassis, transmission, engine) are allocated to a fixed size.

The second vulnerability (or feature) was that the transmission allows modifying any transmission gear as long as the gear index is smaller than the gear_count. However the gear array is sized 4 always and the gear count is not verified to be <= 4, so if we corrupt the gear count, we get a primitive to read/write any byte starting from the transmission->gear up to 0xFFFF.

Except... that actually the transmission->gear_cnt was not a short but a qword and the index requested into it was a qword as well. This means that here we already had the opportunity for a complete arbitrary rw instead of a write up to offset 0xFFFF. Consequently.. the writeup as follows is a slight bit over-engineered :) The spoiler would be, of course, that once you overlapped the tire and the transmission and modified the 64 bits of the transmission->gear_cnt, then you have the fully powerful primitive to read/write anything-anywhre. Not so hard from there, is it. o.O

# exploit primitives

This challenge was not PIE and not RELRO. Therefore it was immediately clear that we will want to target a GOT overwrite. (It actually could have been done without it also, see the final notes.) And first it looked like we could do a classic free->system overwrite as the frees are called on the end on some objects where we can nicely control the contents. But, the order wasn't right and this failed on calling system() with junk first. So we resorted to trying one-gadget rce, which worked anyway.

The second important primitive was that we can reallocate car parts as many times as we liked. They weren't ever freed normally, simply just the reference to the previously allocated tire/transmission/chassis/engine was lost. There was one exception: IF an engine was to be replaced AND it was allocated from the slot allocator, then it would be freed. But actually only tires are ever allocated possibly from the slot allocator, so this wasn't triggerable normally. Could be with corruptions but this was unnecessary.

The third primitive was the control we had over allocated objects. The main thing was that the first six bytes of tires could be modified completely arbitrarily, and then gears of transmissions by byte also could be modified arbitrarily. So if we can overlap a tire and a transmission, then modifying the width of the tire modifies the gear count of the transmission, which in turn allows reading and writing bytes at an arbitrary unsigned short offset from the transmission object's gears field.

Another primitive that could have been useful is that the arena object had a field that was rather peculiar. This was set to 0 and never set by anything, however, at the game's end, IF it was set, then it was treated as an object pointer, with two fields: a function pointer and a data pointer, on which fn(data) was called. It would seem that the goal was to corrupt this field in order to trigger system("/bin/sh") this way of course. However, we exploited the challenge differently in the end, so never used this field. At the end of the write-up, this second approach is explained in broad strokes.

# exploit challenges

We can see that the transmission-tire overlap gives us a very powerful corruption primitive.
But we still need something to target. We decided to go after arenas, in order to control the data_start where we allocate from, therefore giving us a way to overlap the GOT.

We also need libc + heap leak. Heap leak is straightforward from the primitive since game objects have many heap pointers like data_start, data_end, etc. Libc leak would come trivially once we overlap the GOT.

Since the main arena is always allocated at the very beginning, this couldn't be our target. Instead, we played with filling up arena so that we would trigger new arenas sequentially after where we created the overlapped and corrupted tire/transmission.

The last challenge we had because of the target we picked (arena corruption -> GOT overwrite). Since there is the buggy behavior of allowing zero sized allocations, regardless of managing to wrap an arena->data_start onto the GOT, we would only succeed at allocating non-0 sized allocations from here even when the main arena is full, because 0 sized allocations succeed in a full arena anyway. Therefore, we had to also trigger moving the main_arena->list_head, so that we would not attempt (and erroneously succed at) allocating a zero sized tire from the main arena.

# exploit steps

The full exploit is in rw.py. It has detailed comments for the steps, briefly:

* fill up the main arena almost fully with tires
* allocate a zero sized tire and a transmission to overlap the two at the end of main_arena
* allocate one more chassis and engine, this triggers allocation of a second arena plus it gives us the full car we need so that we can go to the modification menu
* modify the tire width that will overlap with the transmission gear count, giving us an out-of-array read-write primitive.
* yet again buy a lot of tires so that we fill up the second arena almost
* now corrupt the second arena with the r/w primitive. since we kept our transmission, we can still use it irectly.
* first we read out the arena's data_ptr which gives us a heap leak
* then we modify the next pointer of the second arena to create a fake arena
* and we modify the iterator count of the second arena so that its next can be chosen as the new list_head, making fake arena the list head when yet another new arena creation is triggered
* then we construct the fake arena, after the second arena's control structures (this corrupts some allocted old parts but who cares)
* the fake arena will have a next of 0, a data start pointing to the GOT and data_end pointing there too, so that it looks full. It has to look full so that the creation of the third arena is triggered and has to have a zero next so that iteration stops here.
* write the max allocation size field of the fake arena for sanity (0xfff)
* now we buy some more chassis so we trigger the creation of the third arena. This not only creates a third arena but also makes the fake_arena the list_head
* now that we made fake arena the list_head, we can again corrupt its data_end so that now it looks like it has space for allocations, this way NOW when we trigger an allocation: main arena is skipped since it is no longer the list_head, because fake arena is the list head, so we can go to the fake arena and allocate from there, therefore we allocate from the GOT.
* finally - we can allocate once again overlapping 0 sized tire + a transmission, this time they go to the GOT
* same steps to get r/w primitive via the modified transmission gear count and overwrite the free pointer in the GOT to get rce.

# final exploit

rw.py

# final note

There is at least one alternative solution to this challenge that we didn't use. Instead of targetting a second arena for overwrites, we could have targeted a slot object and combine that with the normally unused object field of the main arena. In broad strokes: after getting a tire around the end of the main arena overlapped with a transmission, allocate a large tire that will create a new slot first and then a tire. Now read the data_ptr of the slot to get heap leak. Then, write the next of the slot from 0 to the main_arena+0x40 to overlap with the never_initialized_obj. Then trigger another large tire allocation -> first slot is full so it goes to its next which looks empty so it puts the allocated data_ptr into main_arena->never_initialized_obj. It will also corrupt the next_slot field overlapping the "nothing_" field of the main_arena, which (intentionally?) was unused. Now we have a tire that is the never_initialized_obj. Through all of this, we still maintained our transmission r/w primitive and in fact since there's no second arena yet, it can still reach the malloc'd tire. So we can modify all fields of the tire easily to get a fake funtion pointer and data field. In order to get a libc address though, in this scenario we would need a chunk in the unsorted bin in order to leak libc address from the heap. This could be achieved by corrupting the data_ptr of slot first, so that it seems to point to an engine, trigger the free_engine() and get a "wild free" which can fairly easily be survived (needs some field changing in front of the engine, but again the transmission can help here, plus also after it. we would have needed to set a good size field with a prev_inuse bit at -8, plus we would have needed to have an inuse bit for the chunk at engine+size, which we would get if we just picked size so that it would align with an actual allocated chunk of malloc) to place the engine onto the unsorted bin. Then we can leak that libc pointer and finish by triggering the perhaps more elegant system("/bin/sh"). Anyway - easy does it.
