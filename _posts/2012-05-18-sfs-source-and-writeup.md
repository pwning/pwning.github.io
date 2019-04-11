---
title: sfs source and writeup
authors:
  - ricky
layout: post
categories:
  - Pwn
ctf: PlaidCTF
year: 2012
---
This is the second of a series of posts where we'll give our solutions (as well as source code) for some problems from Plaid CTF 2012.

## Source code

  * [problem.cc][1]
  * [problem.h][2]

## Overview

sfs (Secure File System) was a 64-bit C++ binary (PIE) running under xinetd on a Debian machine with NX and ASLR enabled.

<!--more-->

The program gives you an interface to a "filesystem" which encrypts its files with either RC4 or xor with a string. The interface looks something like this:

```
$ ./problem
Password: Ve3yhTFW9TsffX2J
Welcome to the encrypted file system!

create [file] [xor|rc4] [key]  Create file (xor or rc4)
ln [target] [linkname]         Create hard link
mkdir [dir]                    Make directory
cat [file]                     View file
edit [file] [key]              Edit file
rm [file]                      Delete file
rmdir [dir]                    Delete directory
ls [dir]                       List directory
cd [dir]                       Change directory
help                           Show list of commands
exit                           Exit

user@/$
```

A file is represented as a NormalFile class, which has a pointer to a FileData class. When a hardlink to a file is created, the hardlink shares the original file's FileData. The number of NormalFiles referencing a FileData is kept track of with a 8 bit reference counter in the FileData class.

## Vulnerability

There were (at least) two use-after-free vulnerabilities in this program. The first one (which I didn't intend to put in) occurs when trying to create a hardlink with the target in a nonexistent directory. [@sleepya_][3] has a great [writeup][4] of exploiting this vulnerability.

The vulnerability that I intended for people to exploit was that it was possible to cause a FileData's reference counter to wrap back around to 1 by creating 256 hard links to a file. If we then delete one of the files, the FileData will be freed even though it is still referenced by 256 other NormalFiles.

## Exploitation

To exploit this vulnerability, we first want to find out where the heap and libc are. We can then try to overwrite a FileData's vtable in order to control rip and do ROP.

Here's an outline of what the exploit does:

1. Create a file A, and make 256 hardlinks to it (A0, A1, &#8230;).
2. Create a file B, and make 256 hardlinks to it (B0, B1, &#8230;).
3. Delete A and B. This causes the FileData for all of A's and B's hardlinks to be freed.
4. Leak a heap address by reading A0.
5. Leak a libc address by reading B0.
6. Create a file C containing a fake vtable and ROP payload.
7. Create a file D (its FileData will overlap with A0's FileData) containing the address of our fake vtable in its FileData.
8. Edit A0, causing it to call a function from our fake vtable, and thus letting us control %rip.
9. ROP ROP ROP!

In order to do ROP, I used a nice gadget from the setcontext function, which basically sets all of the registers to values at offsets from its first argument.

```
00000000000439c0 &lt;setcontext>:
...
   439f5:   48 8b a7 a0 00 00 00    mov    0xa0(%rdi),%rsp
   439fc:   48 8b 9f 80 00 00 00    mov    0x80(%rdi),%rbx
   43a03:   48 8b 6f 78             mov    0x78(%rdi),%rbp
   43a07:   4c 8b 67 48             mov    0x48(%rdi),%r12
   43a0b:   4c 8b 6f 50             mov    0x50(%rdi),%r13
   43a0f:   4c 8b 77 58             mov    0x58(%rdi),%r14
   43a13:   4c 8b 7f 60             mov    0x60(%rdi),%r15
   43a17:   48 8b 8f a8 00 00 00    mov    0xa8(%rdi),%rcx
   43a1e:   51                      push   %rcx
   43a1f:   48 8b 77 70             mov    0x70(%rdi),%rsi
   43a23:   48 8b 97 88 00 00 00    mov    0x88(%rdi),%rdx
   43a2a:   48 8b 8f 98 00 00 00    mov    0x98(%rdi),%rcx
   43a31:   4c 8b 47 28             mov    0x28(%rdi),%r8
   43a35:   4c 8b 4f 30             mov    0x30(%rdi),%r9
   43a39:   48 8b 7f 68             mov    0x68(%rdi),%rdi
   43a3d:   31 c0                   xor    %eax,%eax
   43a3f:   c3                      retq
```

Here is our exploit for this problem: [exploit.py][5].

 [1]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/problem.cc
 [2]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/problem.h
 [3]: https://twitter.com/#!/sleepya_
 [4]: http://auntitled.blogspot.com/2012/05/plaid-ctf-2012-secure-fs.html
 [5]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/exploit.py_.txt