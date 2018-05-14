# itsame DC 2018 Quals

This was a heap memory corruption challenge, dressed up as a fairly racist depiction of an Italian Pizza restaurant.

The implementation was C++ although the only custom object was for Pizzas. However, users, ingredients, and pizzas were all kept as std::vector<> and ingredient names as std::basic_str.

Mario's restaurant allows us to create new customers and log in as customers, simply by name. The currently logged in customer can order pizzas by selecting ingredients and ask to cook all pizzas. As long as pizzas are cooked successfully, they can be admired. So these objects never leave the game, cooked pizzas remain forever, created users remain forever.

The important added state is that Mario does not allow pineapple on its pizzas. If a pineapple ingredient is requested, he refuses it at the order stage. However if at the cooking stage he finds that a pizza has been ordered with a pineapple ingredient anyway (first vulnerability triggers this), then he gets angry at the user. This makes the user the designated upsetting user. If this happens, then the user can no longer (ever) order, cook, or admire pizzas, but a new menu options allows to try to provide an explanation for Mario. Actually Mario never accepts the explanation, but this further allows the user another menu option of askink Mario why. This menu option does nothing but print the user's name and explanation.

# Vulnerabilies

The first vulnerability allows us to snuggle in the pineapple ingredient. Ingredients must be utf8 chars and the pineapple symbol happens to be 4 bytes (2 unicode characters). When an ingredient is requested, it is checked in itself if it is not the pineapple, which means any valid unicode character (2 byte sequence) is accepted as a candidate ingredient for cooking. On the other hand, when Mario cooks the pizza, the ingredient vector's std::basic_str elements are turned into c strings and concatenated and then this final string is checked with strstr to not contain any pineapples. This way of course we can snuggle in the two pineapple parts and hit the important scenario of upsetting Mario.

Check at ordering pizza ingredient:
```
      while ( ingr_i <= num_ingredients )
      {
        printf("Tell me ingridient #%d: ", ingr_i);
        read_str(ingredient_name, 20);
        if ( (unsigned __int8)is_utf8_test(ingredient_name) ^ 1 )
        {
          puts("what is this? not capisco. I only speak utf8");
        }
        else
        {
          v1 = pineapple_unicode;
          if ( strstr(ingredient_name, pineapple_unicode) )
          {
            logged_in_user->pineable_request_made_mario_upset = 1;
            puts("You serious? PINEAPPLE? Tu sei un pazzo, get out. https://youtu.be/J6dFEtb06nw?t=27");
            v2 = 0;
            goto PINEAPPLE_ERROR;
          }
          st
```

And the way Pizzas are cooked, including the check after assembling ingredients:
```

  printf("Before I start cooking your pizzas, do you have anything to declare? Please explain: ");
  read_str(pizza_explanation, 300); //a local variable
  explanation_len = strlen(pizza_explanation);
  logged_in_user->explanation_ptr = (char *)malloc(explanation_len + 1);
  strcpy(logged_in_user->explanation_ptr, pizza_explanation);
  num_pizzas = std::vector_ingredients::size(&logged_in_user->ingredients_vector, pizza_explanation);
  v15 = 0;
  v16 = 0;
  pizza_ingredient_unicodes = (char *)malloc(400uLL);
  for ( pizza_i = 0; pizza_i < num_pizzas; ++pizza_i )
  for ( pizza_i = 0; pizza_i < num_pizzas; ++pizza_i )
  {
    printf("-------- COOKING PIZZA #%d --------\n", (unsigned int)(pizza_i + 1));
    ingredient_vector = std::vector_ingredients::at(&logged_in_user->ingredients_vector, pizza_i);
    std::vector_ingredients::assign(&l_ingredients_vector, ingredient_vector);
    *pizza_ingredient_unicodes = 0;
    for ( i = std::vector_ingredients::begin(&l_ingredients_vector); ; std::vector_ingredients_it(&i, ingredient_c_str_) )// 
                                                // 
                                                // loop to create c_str rep of concatenated ingredients
    {
      v20 = std::vector_ingredients_back(&l_ingredients_vector);
      v3 = (pizza_t **)&v20;
      if ( !(unsigned __int8)std::vector_ingredients_eq(&i, &v20) )
        break;
      v4 = sub_35B0(&i);
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(
        &ingredient_std::basic_str,
        v4);
      ingredient_c_str = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&ingredient_std::basic_str);
      printf("Adding ingredient: %s\n", ingredient_c_str);
      ingredient_c_str_ = (const char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::c_str(&ingredient_std::basic_str);
      strcat(pizza_ingredient_unicodes, ingredient_c_str_);

		//strcat concats them together here
			
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&ingredient_std::basic_str);
    }

(...)

//next we decide what type of pizza this will be

      if ( strstr(pizza_ingredient_unicodes, &good_ingredient) )// approved is this ingredient is in it
        is_approved_pizza = 1;
      else
        is_bad_pizza = 1;

//since it is a strstr on the concatenated, we can sneak the pineapple back in.

      if ( strstr(pizza_ingredient_unicodes, pineapple_unicode) )
      {
        is_pineapple = 1;
      }
      else if ( strstr(pizza_ingredient_unicodes, &needle)// if any of 3 bad ingredients present -> bad pizza
             || strstr(pizza_ingredient_unicodes, &byte_75EB)
             || strstr(pizza_ingredient_unicodes, &byte_75F0) )
      {
        is_bad_pizza = 1;
      }

//based on pizza type we create a pizza object

      if ( is_approved_pizza )
      {
        pizza_1 = (pizza_t *)operator new(0x38uLL);
        pizza_ingredient_unicodes_ = pizza_ingredient_unicodes;
        ApprovedPizza_init(pizza_1, pizza_ingredient_unicodes);
        pizza_selected = pizza_1;
      }
      else if ( is_bad_pizza )
      {
        pizza_2 = (pizza_t *)operator new(0x38uLL);
        pizza_ingredient_unicodes_ = pizza_ingredient_unicodes;
        BadPizza_init(pizza_2, (__int64)pizza_ingredient_unicodes);
        pizza_selected = pizza_2;
      }
      else
      {
        if ( !is_pineapple )
          _assert_fail("false", "customer.h", 0xB5u, "void Customer::cook_pizzas()");
        pizza_3 = (pizza_t *)operator new(0x38uLL);
        pizza_ingredient_unicodes_ = pizza_ingredient_unicodes;
        CriminalPizza_init(pizza_3, (__int64)pizza_ingredient_unicodes);
        pizza_selected = pizza_3;
      }

//the main point of making Pizzas inherited objects is to allow for vtables in the Pizza object which will serve as the target of memory corruption for RIP control in the end. Note that we don't target pizza cooking virtual function but the pizza admiring virtual function.

      puts("Cooked new pizza:");
      (*(void (__fastcall **)(pizza_t *, char *))(pizza_selected->vtable + 8))(
        pizza_selected,
        pizza_ingredient_unicodes_);

//finally - we set the upsetting user because Pineapple was found.


      if ( is_pineapple )
      {
        printf(
          "HOW IS IT POSSIBLE??? %s here?? How could this order get here? this pizza is criminal.\n",
          pineapple_unicode);
        printf("And this is the only thing you could say about your order: %s\n", logged_in_user->explanation_ptr);
        puts("are you serious?");
        upsetting_user = logged_in_user;
      }

```

Another key aspect of the Pizza cooking is that the explanation of the user is actually allocated right before cooking already as can be seen above. This leads directly the second vulnerability, which was apparent already from the way the user struct is created - there was no size field for the explanation, despite the explanation dynamically allocated based on the user provided size.

And indeed, when we get to the upset part, the copying of a new explanation allows 300 bytes. This means up to 299 byte overflow on the heap.

```
      case 'P':                                 // Please Mario
        if ( logged_in_is_the_upsetting_user )
        {
          printf("last chance, explain yourself: ");
          read_str(logged_in_user->explanation_ptr, 300);
          puts("too bad, no explanation is reasonable. BAM BAM BAM!");
          logged_in_user->pineable_request_made_mario_upset = 1;
        }
        break;
```

# Exploit Steps

Since the binary was PIE, we needed to get a leak of the heap and the libc addresses. With a heap leak, we can construct a fake Pizza vtable on the heap that wee can know the address of; with the libc leak we can put the address of a RIP control target (one-gagdet RCE does the trick) into the fake vtable. Then the buffer overflow can be used to actually corrupt the vtable of a pizza object.

In order to get a heap and libc leak, we can leverage the behavior of the standard allocator. Linked together fastbin sized free chunks will include an fd that will be a pointer to the heap. Whereas unsorted bin chunks will include and fd/bk that will give us a libc address.

First, we can target the heap leak. The difficulty to realize is that our writesof explanations always get \0 terminated. So we can't arbitrarily modify things. We will target a user structure, which starts with the username pointer. By overflowing it by exactly one byte, the \0 will replace the LSB og the username pointer with 0. So we have to organize the heap such that this offset moves the unsername from the intended into an address where the fd of a fastbin chunk is. Finally we leak this out using the "Why" menu point.

Second is easier. Once we have the heap leak, we can know the exact address of an unsorted bin chunk, so we fully overwrite a username pointer instead of partially and get the libc leak from there.

To get the rce with all that, we can target the invocation of pizza admiring:

```

__int64 __fastcall handle_AdmireCookedPizzas(user_t *logged_in_user)
{
  __int64 v1; // rax
  __int64 i; // [rsp+10h] [rbp-1930h]
  __int64 v4; // [rsp+20h] [rbp-1920h]
  void (__fastcall ***pizza_this)(_QWORD, char *); // [rsp+28h] [rbp-1918h]
  char s[6400]; // [rsp+30h] [rbp-1910h]
  unsigned __int64 v7; // [rsp+1938h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  if ( std::vector_pizza::size(&logged_in_user->pizza_vector) == 0 )
    printf("You have nothing to admire, %s\n", &unicode_banner_sg);
  v1 = std::vector_pizza::size(&logged_in_user->pizza_vector);
  printf("Admire these beauties... (%lu)\n", v1);
  for ( i = std::vector_pizza_begin(&logged_in_user->pizza_vector); ; std::vector_pizza_it(&i) )
  {
    v4 = std::vector_pizza_back((__int64)&logged_in_user->pizza_vector);// terminator condition
    if ( !(unsigned __int8)std::vector_pizza_eq(&i, &v4) )
      break;
    pizza_this = *(void (__fastcall ****)(_QWORD, char *))std::vector_pizza_at((__int64)&i);
    memset(s, 0, 0x1900uLL);
    (**pizza_this)(pizza_this, s);
  }
  return __readfsqword(0x28u) ^ v7;

```

Note that this also means that the user who Mario gets upset with (who can overflow explanation) can NOT be the owner of the pizza object we target here, because only users can admire their pizzas who are not hated by Mario.

# Heap Layout Challenges

This was actually by far the most challenging part of this.

First, because the binary uses std::vector, std::basic_string, and std::allocator, we can several "implicit" allocations on the heap, not only the user, ingredient, concatenated ingredient list, explanation, and pizza objects.

Second, because as we could infer from the game's different states, for the leak steps, we need to be able to corrupt not just any user's structure but the same user's who upsets Mario. And similarly for corrupting a Pizza, it has to be another user's Pizza. That is because once we get the corruption, we can only call the Why on this user, not another. Of course, we could corrupt a user's username and log back in with that user, but the problem is that since we corrupt the username to point to a heap address that contains an unknown string (a heap address itself), we can't pass the login since we can't provide the correct name. At this point we considered writing an exploit that would simply bruteforce the string by attempting logins, but we discarded this due to the entropy and the increased complexity of heap massaging, if at all workable.

Third heap layout problem was that all Pizza cooking creates the concatenated ingredient buffer as a fix 400 byte long buffer which is NEVER freed. The problem with this is that the allocation order therefore is user,username,(...),explanation,ingredient_concat,pizzas. This means that by default we would get a too large blocker buffer after our explanation that would render the 300 byte overflow useless.

Fourth and final difficulty with heap layout, which actually in the end isn't the problem but part of the solution, is all the "implicit" heap actions triggers by std::vector operations which also have to account for.

# Controlling Heap Layout

In the end, we used basically three tricks to continuously get the right layout for the 3 phases (heap leak, libc leak, rip control).

First trick is that if we cook a pizza successfully, the user, username, ingredients concat buffer, pizza objects remain, but the explanation gets freed. This always allow us to create a layout like: user|username|std::vector triggered allocations (more on this in a second)|explanation|400|pizza

So if the explanation is 300 large, we create a gap there where another iteration of user creation can put everything except the 400, so we can have things close enough to an explanation.

The second trick is that we can always attempt to cook pizzas, even if we order nothing. This actually becomes a big nop, except one thing: the explanation object gets allocated - but never freed! This gives us a fully controlled heap spray primitive. We used this in between our steps (heap leak, libc leak, rip) to alway clean up the heap so that we can start from a clean slate. We did this simply with trial-and-error, after each successful step we just checked what pwndbg heap said about unsorted and fastbin chunks and did enough cooking to get rid of all.

The third and by far most important trick (in real time, the vast majority of the effort went into coming up with the way to achieve this, without which nothing would work) was creating the scenario where the explanation can go BEFORE the user object. Remember that sequentially always the user gets allocated first so this could be tricky. What saved us here actually was the std::vector stuff, specifically what happens when ingredients are created.

Basically, if we look at how ingredients are created when we order a pizza, we see that we first allocate on the heap the std::vector for users already part of the user creation, then as part of the ordering we first allocate the std::basic_str for an ingredient, then we allocate the ingredients vector std::vector object, and then actually the assignment of the ingredient into this vector creates a NEW copy of the ingredient std::basic_str and frees up the original. This creats a gap on the heap! The key was that with small enough sized ingredient, that std::basic_str gap will be enough to hold an explanation allocation, but never enough to hold a user. Just like that, we have our condition that we want.

For some explanation, here is a pwndbg heap layout after creating first user, then ordering one pizza with one ingredient:

```
pwndbg> heap
pwndbg> heap
Top Chunk: 0x555555772d20
Last Remainder: 0

0x555555761000 PREV_INUSE {
  prev_size = 0, 
  size = 72721, 
  fd = 0x11c00, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555772c10 FASTBIN {					USER
  prev_size = 0, 			
  size = 81, 
  fd = 0x555555772c70, 
  bk = 0x555555772ce0, 
  fd_nextsize = 0x555555772cf8, 
  bk_nextsize = 0x555555772cf8
}
0x555555772c60 FASTBIN {					USERNAME
  prev_size = 1, 
  size = 33, 
  fd = 0x3172657375, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x21
}
0x555555772c80 FASTBIN {					USERS_VECTOR
  prev_size = 0, 
  size = 33, 
  fd = 0x555555772c20, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x31
}
0x555555772ca0 FASTBIN {					ingredient basic_str FREED UP
  prev_size = 0, 
  size = 49, 
  fd = 0x0, 
  bk = 0x4, 
  fd_nextsize = 0x858d9ff0, 
  bk_nextsize = 0x0
}
0x555555772cd0 FASTBIN {					ingredients_vector (user struct gets a pointer to this)
  prev_size = 0, 
  size = 33, 
  fd = 0x555555772d00, 
  bk = 0x555555772d20, 
  fd_nextsize = 0x555555772d20, 
  bk_nextsize = 0x31
}
0x555555772cf0 FASTBIN {					ingredients basic_ptr replica as the vector was created.
  prev_size = 93824994454816, 
  size = 49, 
  fd = 0x555555772d10, 
  bk = 0x4, 
  fd_nextsize = 0x858d9ff0, 
  bk_nextsize = 0x0
}
```

# Final Exploit

See exp_vek.py
