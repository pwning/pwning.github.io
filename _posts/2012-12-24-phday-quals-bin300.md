---
title: PHDay quals bin300
author: PPP
layout: post
permalink: /?p=1076
categories:
  - General News
---
The recent Positive Hack Days qualifier round had a lot of fun problems. Binary 300 was the only problem that was solved in the competition but not solved by PPP. It was also a very nice crypto problem which was a lot of fun. We ended up having a brute forcer finish the challenge a couple hours too late, which got me interested in seeing how fast a brute forcer could go, if we had more time to write it.

## Problem overview

So to start off, we are given a compiled python file. Decompiling the python bytecode with your favorite tool, we get the following code:

<pre style="padding-left: 30px;">import sys
import hashlib
(5, 1, 3, 6,) = (10018627425667944010192184374616954034932336288972070602267764174849233338727414964592990350312034463496546535924460513481267263055398790908691402854122123L,
 7548218116432136940925610514648634474612691039131890951895054656437277296127635726026902728136306678987800886118938655787775411887815467753774352743068577L,
 6192128262312421513644888506697421915171917575080330421897398651929773466194971539791158995262083381167771056580666419101167108372547406447696753234781064L,
 sys.argv[-1])
if not 6.isalnum() or len(6) &gt; 10:
    raise Exception('Bad pwd')
0 = (chr(len(6)) + 6) * 32
2 = pow(1, int(0[:64].encode('hex'), 16), 5)
if 3 != 2:
    print hex(2)
else:
    print hashlib.md5(6).hexdigest()</pre>

&nbsp;

Anyway, we can see that this is a pretty straightforward problem, the user input is converted to hex and prepended with its length, and then repeated a number of times to give is a 512 bit exponent. We then raise *g* to this power modulo *p*, and compare it to our target value, *x*. If they match, we will get our key!

## Solution

However, this straightforward problem looks an awful lot like the standard <a href="http://en.wikipedia.org/wiki/Discrete_logarithm" target="_blank">discrete logarithm</a> problem. Unfortunately, discrete log is pretty hard to do quickly, leaving us out of luck. A brute force solution would require that we try on the order of  2<sup>60</sup> modular exponentiations, which would be far more than feasible in the time allotted. Luckily, this problem lends itself very well to a <a href="http://en.wikipedia.org/wiki/Meet-in-the-middle_attack" target="_blank">meet-in-the-middle attack</a>, which is a special time-memory tradeoff technique.

Rather than performing all 2<sup>60</sup> modular exponentiations, what we can do is to break our potential exponents in half, let&#8217;s call them *el<sub>i</sub>* and *er<sub>i</sub>* for exponent left and exponent right. We can then generate two tables. In the first, we will raise *g* to each of *el<sub>i</sub>*, and in the second, we divide our target value *x* by g raised to each of our *er<sub>i</sub>* values. Then we will search through our tables to find a value in common. That is, we wish to find an *m* such that *g* raised to the *el<sub>i</sub>* is equal to *x* divided by *g* raised to the *er<sub>i</sub>*, which means that the concatenation of *el<sub>i</sub>* and **er<sub>i  </sub>**will be the full exponent.

From a theoretical standpoint, that&#8217;s all there is to this problem. We&#8217;ve reduced 60 bits of security to about 30, which is great. However, we want to actually get a key out of this* and fast*. It turns out that modular exponentiation, especially to 512 bit, is quite slow, and on a single good computer, a naive solution to this problem will take many hours (see <a href="http://nightsite.info/blog/7042-phd-quals-2012-binary-300.html" target="_blank">this writeup</a>). Sometimes in a CTF this is fine, but if we have the chance, why not do things a little better 😉

## Optimizations

To make this go fast, we&#8217;re going to code it up on GPUs. Most brute force problems are easily parallelized, I happen to have a machine with a few reasonable GPUs, and I&#8217;ve been meaning to mess around with OpenCL more, so this seems like a good opportunity. The downsides of writing GPU code is that there are no libraries (that I know of) for arbitrary, or even 512 bit arithmetic already implemented. Luckily this isn&#8217;t too hard to do.

Now, hopefully everyone is aware of the standard algorithms for modular exponentiation. The <a href="http://www.tricki.org/article/To_work_out_powers_mod_n_use_repeated_squaring" target="_blank">repeated squaring algorithm</a> is the most popular, and works pretty well in most cases. The basic idea is to use the binary representation of our exponent, and to repeatedly square *g* to fill in each of the spots with 1s. This results in only a logarithmic number of multiplies of 512 bit numbers and modulo *p* steps. Unfortunately, modulo *p* amounts to 512 bit division, which is quite slow. We can replace this by using <a href="http://en.wikipedia.org/wiki/Montgomery_reduction" target="_blank">Montgomery Reduction</a> (this was actually a new technique to me, and was pointed out by Reinhart, one of the great guys from <a href="http://eindbazen.net/" target="_blank">Eindbazen</a>).

Montgomery Reduction is great, because it is a bit easier to program, and it&#8217;s also a bit faster. Our OpenCL implementation probably provides very little actual benefit compared to just taking our answers modulo *p*, but if we were using other platforms that natively supported a few more of our operations, then it would be far more beneficial. It also still allows us to use repeated squaring, which we know is very fast.

The next speedup comes from precomputing each of the possible *g* raised to powers of 2. By providing a lookup table for these, we can avoid quite a few multiplications that we would otherwise end up repeating every time we calculate an exponentiation. Again, this also not only helps our code performance, but also makes things a bit easier to program.

At this point, a single GPU will get around 100 thousand modular exponentiations per second, which seems great. However, once we start using larger numbers (or more precisely, numbers with higher hamming weights), this rate starts dropping pretty fast. For full, 512 bit exponents, our rates are closer to 10 thousand modular exponentiations, which is a bit too slow for our tastes. So what can we do to fix this?

Again, we can use precomputation to fix this issue. We can break up our exponent into just four or five different pieces; one for each character in the half key we are using. For example, if we are calculating the key half for &#8220;abcde&#8221;, our exponent is

<pre>0x09616263646500000000096162636465000000000961626364650000000009616263646500000000096162636465000000000961626364650000000009616263</pre>

This has a hamming weight of 126, which means a naive repeated squaring solution would require 126 multiplications to calculate the exponent.

However, we can easily break this value apart. For example, when testing 9 character strings, we know that the key will always have the bits set

<pre>0x0<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>0000000000000000000<span style="color: #ff0000;">9</span>000000</pre>

Similarly, for a character with hex value XX, the exponent will have a mask of bits set

<pre>0x00<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>000000000000000000<span style="color: #ff0000;">XX</span>0000</pre>

Because these are disjoint masks for each character that are later added together, this means we can precalculate *g* raised to each of these &#8220;masks&#8221;, and then multiply them together separately.

This mask generation requires precomputation of 4 or 5 times the number of characters in our characterset, 62. Now, using this precomputation, we go from having 126 modular multiplications to only 5! This brings our exponentiation speed back to the range of 100 thousand per second per GPU.

At this point, our GPU machine will give us our two tables (our left key half and right key half) in about 7 minutes! The first thing to do is to not store all 512 bits of the result. With around 100 million entires in 2 tables, that amounts to around 10 gigabytes of data. Luckily modular exponentiation is a good hash function, which means that any subset of bits we look at will have a mostly uniform distribution. Doing the math, we see that we need about 60 bits of data to avoid accidental collisions from the birthday bound, so we&#8217;ll just use 64 bits. This brings us back down to around 1 gigabyte worth of tables.

Now we just need to find the mid-point. Obviously the simple way to find this point is to try all combinations, which is O(n<sup>2</sup>). With a hundred million table entries, this seems like a bad idea.

Sorting both of these tables can be done in O(n log n), and then we can simply do a simultaneous linear sweep to find a point in common. Sadly, the machine I happen to have with GPUs only has 2GB of RAM. What we do is simply sort a portion of the list, and do a parallel binary search with our GPUs to search that section for the midpoint. This keeps our RAM usage low, and is still quite fast.

This takes another 7 minutes or so on our machine, and gives us our discrete log key.

<pre>$ time python oclb.py
compiling OpenCL kernel...
/usr/local/lib/python2.6/dist-packages/pyopencl-2012.1-py2.6-linux-x86_64.egg/pyopencl/__init__.py:36: CompilerWarning: Non-empty compiler output encountered. Set the environment variable PYOPENCL_COMPILER_OUTPUT=1 to see more.
  "to see more.", CompilerWarning)
precomp round 1...
precomp round 3...
Work items: 18
[XXXXXXXXXXXXXXXXXX] Completed Time: 434.83
Work items: 10
[XXXXXXXXXX] Completed Time: 103.13
Work items: 10
[XXXXXXXXXX] Completed Time: 105.03
Work items: 10
[XXXXXXXXXX] Completed Time: 84.37
Work items: 10
[     XXXXX] Time so far: 50.40
FOUND
kA0xSmk39

real    16m15.730s
user    0m31.040s
sys     1m7.680s</pre>

So, our discrete log key is kA0xSmk39, which we can confirm pretty easily. And taking the md5sum of this presumably would give us the key to score points during the CTF.

Feel free to take a look at the python driver and OpenCL code, available <a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/12/bin300.tar" target="_blank">here,</a> just be warned that it is still hacked together and buggy!