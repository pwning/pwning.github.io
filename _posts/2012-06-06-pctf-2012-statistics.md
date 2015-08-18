---
title: pCTF 2012 Statistics
author: mserrano
layout: post
permalink: /?p=834
categories:
  - General News
  - Report
---
As many of you know, PPP recently ran its own CTF: PlaidCTF. As running a CTF tends to produce a lot of data, we thought it might be interesting to have a look at some of the statistics related to this data.

Upon first looking at the pCTF data, I was curious about the kinds of problems that were solved &#8211; as in, was one category more particularly heavily solved than another? Furthermore, how well did we do at weighting problems by difficulty?

<!--more-->

To look at this, I first glanced at how many problems were solved in each category. A little fooling around with the database led to the following barplot:

<a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/categories_solved_sized.png" class="highslide" onclick="return hs.expand(this)"><img src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/categories_solved_sized.png" alt="categories solved" title="Click to enlarge" height="120" width="107" /></a>

A glance at the barplot provides a few surprises. Our most solved category was easily the &#8220;puzzles&#8221; category which contained our two trivia questions. As the answers to both questions were a Google search or some knowledge away, and hence involved minimal work, it&#8217;s no surprise that it was the most solved. With about two thirds as many solutions come &#8220;Potpourri&#8221; &#8211; our section for miscellaneous problems that didn&#8217;t really fit any category. Considering that this category contained the problems 3D and The Game, each worth 100 points, and solved by large numbers of teams, it comes as no surprise that this category was heavily solved.

Swiftly following Potpourri comes &#8220;Pirating&#8221; &#8211; our reversing and forensics section. As this was our largest section, with 13 total problems, it is a little surprising that it didn&#8217;t beat out Potpourri for total solutions. However, many of the problems in this section were harder than previously thought (though some were easier). No problem in this section was solved by more than 50 teams &#8211; including the 50-point Supercomputer 1, which was solved by 48. In fact, the majority of the problems in this section were solved by under 20 teams, with one (Traitor) being solved by none. The increased difficulty of this section in comparison to some of the problems in Potpourri hence explains its lower solution rate.

Following Pirating come &#8220;Practical Packets&#8221; (web and network capture problems) and &#8220;Password Guessing&#8221; (a probably misnamed cryptography section). These are roughly in their expected position, considering that there are relatively few problems in each.

Last comes Pwnables &#8211; our vulnerability exploitation section. While this category had more problems than Practical Packets or Potpourri, the difficulty of the problems in this section was expected to be substantially higher. Whereas most of the other categories had only a couple of truly difficult problems, fully half of the Pwnables problems were rated over 400 points. Of these 3 problems, only one was solved (FPU, by Hates Irony). PPP&#8217;s focus on binary problems (so, reversing and vulnerability exploitation) shows itself again in the reduced solution/problem ratio of this section.

While information about the relative solution rates for categories is interesting, it is probably more interesting to look at the number of solutions for individual problems. After a little more fiddling, this next barplot was produced:

<a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/problems_solved_sized.png" class="highslide" onclick="return hs.expand(this)"><img src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/problems_solved_sized.png" alt="problems solved" title="Click to enlarge" height="120" width="107" /></a>

This data contains relatively few surprises. However, it is interesting to note that Mess had more solutions than expected, and that Bunyan had far fewer solutions than expected. It is also unusual, though far from outside of the realm of statistical probability, that Bunyan, SIMD, Debit or Credit, and Simple all had the same number of solutions.

Of more direct interest is how many problems were solved relative to the value of those problems. After a little fiddling, we obtained this plot:

<a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/values_solved_sized.png" class="highslide" onclick="return hs.expand(this)"><img src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/values_solved_sized.png" alt="problems solved" title="Click to enlarge" height="120" width="107" /></a>

This plot, unfortunately, is highly misleading, as it does not account for how many problems are worth each different value. After normalizing the graph, we obtain a slightly different picture:

<a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/values_solved_norm_sized.png" class="highslide" onclick="return hs.expand(this)"><img src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/values_solved_norm_sized.png" alt="problems solved" title="Click to enlarge" height="120" width="107" /></a>

Even so, this leads us to believe that we may have overvalued our 500-point problem, since it had many more solutions per problem than any of other 200+-point categories. However, a full decision as to how well we predicted the difficulty of these problems must wait for a couple of regressions. First, we seek a regression between the value of a problem and the number of solutions to that problem:

<div class="textwrapper">
  <a href="pctfstats2012/solved_vs_values.html" onclick="return hs.htmlExpand(this, { objectType: 'ajax', contentId: 'highslide-html-5' } )" class="highslide"><br /> View analysis<br /> </a></p> 
  
  <div class="highslide-html-content" id="highslide-html-5" style="padding: 15px; width: auto">
    <div style="height:20px; padding: 5px; border-bottom: 1px solid silver">
      <a href="#" onclick="return hs.close(this)" class="control">Close</a> <a href="#" onclick="return false" class="highslide-move control">Move</a>
    </div>
    
    <div class="highslide-body" style="padding: 10px">
    </div></p>
  </div></p>
</div>

In other words, about 40% of the variation in the count of solutions to a problem can be explained by the variation of the problem&#8217;s point value. This isn&#8217;t too bad, but is far from the only measure of a problem&#8217;s difficulty. However, a quick glance at the graph shows that this number may be misleading &#8211; while there is a clear link between the two values, the link is very much nonlinear, seeming much closer to 1/x. With that in mind, we also looked at the amount of time it took to solve problems of various point values:

<div class="textwrapper">
  <a href="pctfstats2012/values_vs_time.html" onclick="return hs.htmlExpand(this, { objectType: 'ajax', contentId: 'highslide-html-6' } )" class="highslide"><br /> View analysis<br /> </a></p> 
  
  <div class="highslide-html-content" id="highslide-html-6" style="padding: 15px; width: auto">
    <div style="height:20px; padding: 5px; border-bottom: 1px solid silver">
      <a href="#" onclick="return hs.close(this)" class="control">Close</a> <a href="#" onclick="return false" class="highslide-move control">Move</a>
    </div>
    
    <div class="highslide-body" style="padding: 10px">
    </div></p>
  </div></p>
</div>

In other words, about 50% of the variation in the amount of time it took to solve the problem (measured above as the difference between the unix timestamp of the problem being opened and the unix timestamp of the first solution) can be explained by the variation in the problem&#8217;s point value. This is pretty good &#8211; but once again, the graph shows that our function is most likely not linear and in fact likely to be convex.

In the end, this suggests that we did pretty well in valuing and writing problems &#8211; and, while there were a few hiccups here and there, the system generally worked out.

After looking at our performance, we chose to look at how teams playing in the CTF performed. To do so, we first looked at the number of correct solutions submitted, and how that relates to the total score of the team:

<div class="textwrapper">
  <a href="pctfstats2012/solved_vs_points.html" onclick="return hs.htmlExpand(this, { objectType: 'ajax', contentId: 'highslide-html-7' } )" class="highslide"><br /> View analysis<br /> </a></p> 
  
  <div class="highslide-html-content" id="highslide-html-7" style="padding: 15px; width: auto">
    <div style="height:20px; padding: 5px; border-bottom: 1px solid silver">
      <a href="#" onclick="return hs.close(this)" class="control">Close</a> <a href="#" onclick="return false" class="highslide-move control">Move</a>
    </div>
    
    <div class="highslide-body" style="padding: 10px">
    </div></p>
  </div></p>
</div>

Unsurprisingly, this is a very good predictor of performance &#8211; and while once again our fit is nonlinear, a full 94% of the variation in total points scored can be explained by the variation in number of problems solved. After this, we decided to look at points as they relate to total submissions, both correct and incorrect:

<a href="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/brute_force_doesnt_work.png" class="highslide" onclick="return hs.expand(this)"><img src="http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/05/brute_force_doesnt_work.png" alt="points-vs-total-submissions" title="Click to enlarge" height="120" width="107" /></a>

For this particular graph, a regression would clearly be misleading. While the regression line would be positive, it would not be a particularly good regression: the presence of large outliers at &#8220;small&#8221; numbers of submissions and of large influential points at very, very many submissions and very, very few points leads us to believe that there does not exist a strong correlation here.

However, it does confirm for us that *brute force doesn&#8217;t work*, as the teams that attempted large-scale brute force (or just tried a lot of things, or the same thing a bunch of times) did not end up scoring highly, whereas several teams that didn&#8217;t &#8211; such as Eindbazen, which submitted far fewer solutions than most of the rest of the top handful of teams &#8211; scored very highly.

With this information under our belts, we decided to try and see what the outcome of our CTF would have been if we had used a &#8220;self-correcting&#8221; scoring system: namely, a system in which the value of each problem is 1/N, where N is the number of teams that have solved that problem. While the data below is inaccurate, as teams would likely have pursued different strategies with that scoring system in place, it is slightly telling:

<div class="textwrapper">
  <a href="pctfstats2012/replacement_table.htm" onclick="return hs.htmlExpand(this, { objectType: 'ajax', contentId: 'highslide-html-8' } )" class="highslide"><br /> View Table<br /> </a></p> 
  
  <div class="highslide-html-content" id="highslide-html-8" style="padding: 15px; width: auto">
    <div style="height:20px; padding: 5px; border-bottom: 1px solid silver">
      <a href="#" onclick="return hs.close(this)" class="control">Close</a> <a href="#" onclick="return false" class="highslide-move control">Move</a>
    </div>
    
    <div class="highslide-body" style="padding: 10px">
    </div></p>
  </div></p>
</div>

Most notable in this alternative scoring scheme is the fact that Hates Irony moves into 1st, VAND makes a jump of several places, and More Smoked Leet Chicken drops into 3rd. While once again this data is perhaps misleading as teams would likely have tried different strategies, it is still interesting to note what this shows about various team playstyles.

If there&#8217;s any other stats you&#8217;d like us to run, please ask away in the channel #pwning on freenode!