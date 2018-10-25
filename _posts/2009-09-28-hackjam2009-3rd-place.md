---
title: 'HackJam2009 &#8211; 3rd place'
author: PPP
layout: post
categories:
  - General News
---
Congratz to us!

We won 3rd place on HackJam2009 which was held on Sept. 19th for 48 hours.

<div id="attachment_54" style="width: 460px" class="wp-caption aligncenter">
  <img class="size-full wp-image-54" title="Scoreboard" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2009/09/Screen-shot-2009-09-21-at-1.53.58-AM-2.png" alt="Scoreboard right after the competition is over" width="450" height="270" />
  
  <p class="wp-caption-text">
    Scoreboard right after the competition is over
  </p>
</div>

It was fun overall, and we learned many things in the process 😀

We had an interview with Cylab Blog at CMU:  
<img class="aligncenter size-full wp-image-60" title="CyBlog-HackJam2009" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2009/09/Screen-shot-2009-09-25-at-4.19.44-PM.png" alt="CyBlog-HackJam2009" width="450" />  
<!--more-->

<table border="0">
  <tr>
    <td>
      <strong>CyBlog:</strong> Describe the nature of this particular CTF contest? And what level of teamwork was required?</p> 
      
      <p>
        <strong>Plaid Parliament Of Pwning:</strong> General format and rules were similar to other CTF contests, where we need to find a key string to proceed to next stage. However, Sapheads – host of HackJam – claimed that they have differentiated their problem sets from others. Unlike usual CTF contests, they tried to relate problems to real world scenarios.<br /> As problems got harder to solve, teamwork became more critical. The more brains that are coming up with ideas, the more successful you are going to be. It is possible that one person to do entire competition, but doing as a team is more effective and faster.
      </p>
      
      <p>
        <strong>CyBlog: </strong>Give us an example or two of the kinds of problems you had to solve?
      </p>
      
      <p>
        <strong>Plaid Parliament Of Pwning:</strong> Most of the problems required a mixture of several categories of techniques. These categories include binary reverse engineering/exploitation, web hacking, and forensic.<br /> First, for an example of a binary exploitation, we needed to exploit a binary with stack protection that was running on the target server. Specifically, it was checking the integrity of the stack.<br /> Also, as an example of a web hacking, we had to use XSS (Cross Site Scripting) and PHP code injection to access confidential data (in this case, the key phrase).<br /> Third, we also had a forensic problem, where we needed to analyze captured network packets and extract various types of data such as zip and VoIP that gives a hint for password.
      </p>
      
      <p>
        <strong>CyBlog:</strong> What was the most challenging problem you solved successfully and how did you do it?
      </p>
      
      <p>
        <strong>Plaid Parliament Of Pwning:</strong> A problem that was both very interesting and challenging involved reconstructing an OpenSSH private key, that was being used for public key authentication, from the core dump of ssh-agent. This problem was unique because we weren&#8217;t trying to exploit some bug or reverse a program, since it involved an open source program whose source code was readily available. Instead, it required you to be able to understand the source code quickly, relate it to what was in memory, and extract the information you needed.<br /> Finding the key in memory wasn&#8217;t too hard. You just needed to follow a couple of pointers and you were at the bytes you need. What made it difficult is the format the key was in: arrays of integers. How does a couple arrays of integers represent the components of an encryption key. Thanks to the source code and Wikipedia, it was trivial to see that each array represented one big number. Then, after sifting through the openSSL source code, which is quite a mess, one can start to imagine how these integers end up representing some really big numbers. And then it is a simple matter of constructing a private key file. Though it was not easy to find documentation for the OpenSSH private keys. Thankfully, after some time, another open source program plus a little luck resulted in a working private key.<br /> Moral of the story, and one that is in the version of openSSH I looked at, letting a program that has your private keys core dump is a really bad idea.
      </p>
      
      <p>
        <strong>CyBlog:</strong> What do such contests teach you about the nature of developing attacks and countermeasures?
      </p>
      
      <p>
        Plaid Parliament Of Pwning: One of the ways that the problems got harder is that they started to implement some countermeasures against buffer overflow attacks. Obviously these countermeasures weren&#8217;t perfect, but they definitely made it more challenging. And this is somewhat realistic: any one with enough time and resources is going to find a way to break your system, the best you can do, for now, is to make it as difficult as you possibly can.
      </p>
      
      <p>
        <strong>CyBlog:</strong> Do you discern any differences in style, skill levels, etc., between hackers from different countries or regions?
      </p>
      
      <p>
        <strong>Plaid Parliament Of Pwning:</strong> What determines the style and skill level between hackers is their past experiences. While the country or region they are from can influence this, it definitely is not a major difference. </td> </tr> </tbody> </table> 
        
        <p>
          Original:<a href="http://www.cyblog.cylab.cmu.edu/2009/09/carnegie-mellons-capture-flag-team.html">http://www.cyblog.cylab.cmu.edu/2009/09/carnegie-mellons-capture-flag-team.html</a>
        </p>