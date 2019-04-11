---
title: Padocon + wgsbd
author: PPP
layout: post
categories: []
---
This weekend PPP decided to do something different and participate in <em>two</em> competitions <em>at the same time</em>. As our school semester just started, our team was missing a few people which hurt us a bit, but those who participated in [Padocon](http://padocon.org/conference2011/) and [wgsbd](http://www.securitybydefault.com/) had a great time!

Padocon started early, and we had a rough time with challenges for a while. There were lots of great challenges, including many deceptively simple looking binaries similar to last year. We also learned a lot when solving some of the forensic challenges.

Of course, 13 hours into Padocon, we began working on wgsbd (CTF hosted by the Spanish group Security by Default). With only 15 challenges, it seemed this competition would be fast, but that was not true at all! Many of the challenges took us quite some time to solve. The web03 problem was incredibly interesting. The page allowed command execution on the server, but limited what could be run severely. Getting around the restrictions so we could read the token involved quite a few especially convoluted web queries, such as:

```
cmd=eval%09read%09a%09$(set%09$(id%09$(printf%09%c%09$((9223372036854775807*2)))
$(printf%09%c%09$((9223372036854775807*2)))help);printf%09%c%09${123})%09$(printf%09
%c%09$PATH)var$(printf%09%c%09$PATH)tmp$(printf%09%c%09$PATH)a;echo%09$a
```

which took quite a lot of brain power and time to figure out.

Of course we were still working on Padocon challenges as well! And for a few hours we pulled ahead to the top team.

By the time we went to sleep, we were doing pretty well in both competitions. Of course, while we were dozing off, other hackers were rushing to take out place, dropping us down a few places in each competition.

After waking up and solving a few more problems, though, we were back in the running. After the 48 hour Padocon ended, we were exhausted, so we all decided to go home and get some rest. A couple days after the competition was over, we were finally awarded a few hundred points because we found and reported numerous accidental vulnerabilities in the Padocon services (we rooted a few of their machines which we weren't supposed to &mdash; oops!). This was enough to bump us up to a final ranking of third.

After a bit of rest followed by some debugging, we were able to get back to work on wgsbd shortly before it ended, coming in a comfortable third place.

All the participants in both competitions did very well, especially GoN, disekt, sur3x5f, int3pids, and painsec.

While doing more than one competition at a time seemed to hurt our scores a little bit, it was a whole lot of fun!