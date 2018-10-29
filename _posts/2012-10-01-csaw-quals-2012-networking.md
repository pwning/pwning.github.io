---
title: 'CSAW Quals 2012 &mdash; Networking'
layout: post
authors:
  - Alex Reece <awreece>
categories:
  - Forensics
ctf: CSAW CTF Quals
year: 2012
---
## Overview

[Network 1][1] is a pcap of a telnet session. A password is sent in plaintext.
[Network 2][2] is a pcap of a web browsing session, during which a message
containing the key is send using a web form.
[Network 3][3] is a pcap of a USB keyboard. Commands to display a key are entered.

<!--more-->

## Writeup

### Network 1

Upon opening the pcap in Wireshark, we see a small amount of packets, identified as telnet. Using Wireshark's "Follow TCP Stream" feature to reconstruct the session, we notice a password sent in response to a login prompt near the beginning of the text. This password is the flag.

#### Network 2

The problem text, "Some dude I know is planning a party at some bar in New York! I really want to go but he's really strict about who gets let in to the party. I managed to find this packet capture of when the dude registered the party but I don't know what else to do. Do you think there's any way you can find out the secret password to get into the party for me?".

Through Wireshark or maybe a little chaosreader, it's clear we're looking at a primarily web-browsing session. Let's try to find the registration "the dude" makes. Reasonable guesses would be that this registration occurred over email, Facebook events/chat/messaging, or through a HTTP POST method to some custom site. I got lucky and guessed the POST method first.

Welp, "brooklyn beat box" it is.

Another way to get at this besides a lucky guess would've been to examine the web pages browsed, and realize that that the site "www.taproom307.com" is about "some bar in New York". Examining the activity on that site would have lead to discovering the same POST request. However, the "lucky guess strategy" is usually the ideal solution for needle-in-haystack problems, because when it works it takes minimal time and effort 😛

#### Network 3

Wireshark again. USB packets! The capture begins with a bunch of status and descriptor requests coming from the host, so it appears that the capture starts as the USB device is plugged in. We can most probably grab useful high-level information about the device in its responses to descriptor requests.

The device calls itself "Teensy Keyboard/Mouse/Joystick" and has a HID Boot-Class keyboard interface (for information about HID descriptors, see [USB HID spec][7]). There are other interfaces, but a packet log of keyboard typing seems a likely CTF problem.

Under this theory, the USB interrupts that make up the bulk of the capture are keystrokes being sent to the host. Either by reading the USB spec or by visual inspection, we see that the third byte of each interrupt is the key code of the key being pressed. The other bytes hold information about modifiers being pressed and other key codes if multiple keys are being pressed, but that information is not necessary to solve this problem.

```
cat keypresses | grep 'Capture Data' | cut -c28-29 | python -c '
# Keycodes from http://www.usb.org/developers/devclass_docs/Hut1_11.pdf
keycodes = "????abcdefghijklmnopqrztuvwxyz1234567890\n??\t -=[]\\?;??,./"
keys = []
try:
  while 1:
    x = raw_input()
    try: keys.append(keycodes[int(x, 16)])
    except: pass
except: pass
print "".join(keys).replace("?", "")
```

Returns

```
rxterm -geometry 12x1=0=0
echo k
rxterm -geometry 12x1=75=0
echo e
rxterm -geometry 12x1=150=0
echo y
rxterm -geometry 12x1=225=0
echo [
rxterm -geometry 12x1=300=0
echo c
rxterm -geometry 12x1=375=0
echo 4
rxterm -geometry 12x1=450=0
echo 8
rxterm -geometry 12x1=525=0
echo b
rxterm -geometry 12x1=600=0
echo a
rxterm -geometry 12x1=675=0
echo 9
rxterm -geometry 12x1=0=40
echo 9
rxterm -geometry 12x1=75=40
echo 3
rxterm -geometry 12x1=150=40
echo d
rxterm -geometry 12x1=225=40
echo 3
rxterm -geometry 12x1=300=40
echo 5
rxterm -geometry 12x1=450=40
echo c
rxterm -geometry 12x1=375=40
echo 3
rxterm -geometry 12x1=525=40
echo a
rxterm -geometry 12x1=600=40
echo ]
```

Looks like we have our key, "c48ba993d35c3a" except that won't work. Read the geometry arguments to see why!

 [1]: https://csawctf.poly.edu/challenges/45b963397aa40d4a0063e0d85e4fe7a1/b7ed020cf1a6d6f9345d843a3c375332/telnet.pcap
 [2]: https://csawctf.poly.edu/challenges/45b963397aa40d4a0063e0d85e4fe7a1/23dce85a4e96a87028cc9a3e662663ce/lemieux.pcap
 [3]: https://csawctf.poly.edu/challenges/45b963397aa40d4a0063e0d85e4fe7a1/35920fea0ae20fa1d2dde73707ae9bc9/dongle.pcap
 [4]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/10/Network1.png
 [5]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/10/Network2.png
 [6]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/10/Network3a.png
 [7]: http://www.usb.org/developers/devclass_docs/HID1_11.pdf
 [8]: http://ppp.cylab.cmu.edu/wordpress/wp-content/uploads/2012/10/Network3b.png