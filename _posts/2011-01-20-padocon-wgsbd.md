---
title: Padocon + wgsbd
author: PPP
layout: post
categories:
  - General News
---
<p style="text-align: center;">
  <div id="attachment_421" style="width: 448px" class="wp-caption aligncenter">
    <img class="size-full wp-image-421 " title="wgsbd + Padocon" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2011/01/title.png" alt="wgsbd + Padocon" width="438" height="174" />
    
    <p class="wp-caption-text">
      wgsbd + Padocon
    </p>
  </div>
  
  <p>
    This weekend PPP decided to do something different and participate in <em>two</em> competitions <em>at the same time</em>. As our school semester just started, our team was missing a few people which hurt us a bit, but those who participated in <a href="http://padocon.org/conference2011/">Padocon</a> and <a href="http://www.securitybydefault.com/">wgsbd</a> had a great time!
  </p>
  
  <p>
    Padocon started early, and we had a rough time with challenges for a while. There were lots of great challenges, including many deceptively simple looking binaries similar to last year. We also learned a lot when solving some of the forensic challenges.
  </p>
  
  <div id="attachment_419" style="width: 592px" class="wp-caption aligncenter">
    <img class="size-full wp-image-419  " title="Thinking very hard" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2011/01/DSC00149.jpg" alt="Thinking very hard" width="582" height="386" />
    
    <p class="wp-caption-text">
      Thinking very hard
    </p>
  </div>
  
  <p>
    Of course, 13 hours into Padocon, we began working on wgsbd (CTF hosted by the Spanish group Security by Default). With only 15 challenges, it seemed this competition would be fast, but that was not true at all! Many of the challenges took us quite some time to solve. The web03 problem was incredibly interesting. The page allowed command execution on the server, but limited what could be run severely. Getting around the restrictions so we could read the token involved quite a few especially convoluted web queries, such as:
  </p>
  
  <blockquote>
    <p>
      cmd=eval%09read%09a%09$(set%09$(id%09$(printf%09%c%09$((9223372036854775807*2)))
    </p>
    
    <p>
      $(printf%09%c%09$((9223372036854775807*2)))help);printf%09%c%09${123})%09$(printf%09
    </p>
    
    <p>
      %c%09$PATH)var$(printf%09%c%09$PATH)tmp$(printf%09%c%09$PATH)a;echo%09$a
    </p>
  </blockquote>
  
  <p>
    which took quite a lot of brain power and time to figure out.
  </p>
  
  <p>
    Of course we were still working on Padocon challenges as well! And for a few hours we pulled ahead to the top team.
  </p>
  
  <p style="text-align: left;">
    <div id="attachment_420" style="width: 597px" class="wp-caption aligncenter">
      <img class="size-full wp-image-420 " title="Scoreboard" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2011/01/DSC00152.jpg" alt="Scoreboard" width="587" height="389" />
      
      <p class="wp-caption-text">
        Almost half way into Padocon, sadly the scores did not stay like this ;)
      </p>
    </div>
    
    <p>
      By the time we went to sleep, we were doing pretty well in both competitions. Of course, while we were dozing off, other hackers were rushing to take out place, dropping us down a few places in each competition.
    </p>
    
    <p style="text-align: left;">
      After waking up and solving a few more problems, though, we were back in the running. After the 48 hour Padocon ended, we were exhausted, so we all decided to go home and get some rest. A couple days after the competition was over, we were finally awarded a few hundred points because we found and reported numerous accidental vulnerabilities in the Padocon services (we rooted a few of their machines which we weren&#8217;t supposed to&#8230; oops!). This was enough to bump us up to a final ranking of third.
    </p>
    
    <p style="text-align: left;">
      <div id="attachment_422" style="width: 563px" class="wp-caption aligncenter">
        <img class="size-full wp-image-422  " title="Karma" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2011/01/DSC00154.jpg" alt="Working on Karma" width="553" height="366" />
        
        <p class="wp-caption-text">
          Must... solve... more... karma binaries!
        </p>
      </div>
      
      <p style="text-align: left;">
        After a bit of rest followed by some debugging, we were able to get back to work on wgsbd shortly before it ended, coming in a comfortable third place.
      </p>
      
      <p style="text-align: left;">
        All the participants in both competitions did very well, especially GoN, disekt, sur3x5f, int3pids, and painsec.
      </p>
      
      <p style="text-align: left;">
        While doing more than one competition at a time seemed to hurt our scores a little bit, it was a whole lot of fun!
      </p>