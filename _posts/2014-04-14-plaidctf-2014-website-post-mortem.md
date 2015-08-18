---
title: 'PlaidCTF 2014 &#8211; Website post-mortem'
author: PPP
layout: post
categories:
  - General News
---
First, we would like to thank everyone for participating in PlaidCTF 2014. Thanks to all of you, this year was bigger than ever with over 850 teams partcipating and 3 <a title="PlaidCTF 2014 Sponsors" href="http://play.plaidctf.com/sponsors" target="_blank">sponsors</a> (THANK YOU!) providing $14K in cash prizes and covering all of our operating costs. Congratulations go out to 0xffa, Dragon Sector, and MoreSmokedLeetChicken for finishing in 1st, 2nd, and 3rd. We hope everyone had a lot of fun with the challenges and maybe learned a thing or two, as well.

Now, as everyone who played pCTF this year noticed, things got off to a very rocky start. This was very disappointing for us because we spent a lot of time this year building a simpler interface that would be more usable and, we hoped, more stable. It turns out that we had a few mistakes materialize during the CTF, some nastiness with a particular WSGI server, and more teams than ever before.

The first issue that came up was with our frontend / caching server. Like previous years, we used nginx to serve the static files, but unlike previous years, we also used nginx as the caching layer instead of varnish. This turned out to be a fatal error because nginx does not support the standard Vary HTTP header, which is used by the backend to distinguish between pages that should be cached based on the cookie and those that should not. As such, *all* pages were cached* without* the cookie which meant a user might see a different team’s page instead of their own. As a quick fix, we added the cookie header to the cache key, but now all of the pages that we thought would be regenerated once per second needed to be regenerated once per second *per team*. And as I will discuss later, we had a lot of teams.

The second issue, and the one that ended up consuming a lot of our time and causing the most frustration, was a strange interaction between nginx and gunicorn. This year we stuck to a pretty standard setup: django + gunicorn + nginx. Unfortunately, due to high load, or other factors that we are still unaware of, gunicorn was hanging on a *recvfrom* call on its socket. The problem mysteriously fixed itself a couple hours into the competition, but then came back an hour or so later. At that point, we started replacing parts of our infrastructure (e.g. nginx -> Apache, gunicorn -> uwsgi). The working setup ended up being uwsgi + nginx, but it took us a couple of hours to get to this point. Now, the backend worker processes were no longer hanging and the website was mostly working except for some load issues.

As I mentioned above, we had more teams this year than ever before with over 850 teams solving the trivial sanity check key. Once the nginx caching was working properly, we found that we were still overloaded during the voting phases so we brought up another copy of the www server and used an Elastic Load Balancer as the new frontend. I would like to thank Amazon for making its load balancer very easy to setup, use, and monitor. After this, all load issues were resolved and the website continued to be stable for the rest of the competition. We lost IP address information for the majority of the competition because we were not logging the X-Forwarded-For header, but that was a small price for having a working website.

<div id="attachment_1206" style="width: 403px" class="wp-caption aligncenter">
  <a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2014/04/ELB-Requests.png"><img class=" wp-image-1206  " alt="Requests per minute processed by the Elastic Load Balancer" src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2014/04/ELB-Requests.png" width="393" height="170" /></a>
  
  <p class="wp-caption-text">
    Requests per minute processed by the Elastic Load Balancer
  </p>
</div>

There were two other bugs in the game logic that we fixed over the course of the 48 hours. The first one was an issue with the database transactions in Django. The default isolation level for the postgresql database backend was “Read Committed” which resulted in transaction interleaving and allowing teams to submit the same key multiple times. We resolved the issue by changing the isolation level and enforcing uniqueness of (team\_id,problem\_key_id) in the database. The other issue was related to the “chance” tiles. During the first half of the competition, it was impossible for the “chance” tile to return something besides “Unlucky!” Once we resolved the problem, we changed the probabilities to compensate for the lost attempts.

All in all, we think the competition went well and we thank everyone for their patience. Every year we try to do something a bit different to keep things interesting and with that comes some untested infrastructure. I assure you that we continue to learn from these mistakes and will continue to work hard to improve the competition for next year.

&#8211; awesie on behalf of PPP