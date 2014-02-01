ggpo
====

&copy;2014 Pau Oliva Fora ([@pof](https://twitter.com/pof))

This is an alternative [GGPO](http://ggpo.net/) command line client written in python.
I have only tested this on Linux but it might work on other platforms.
You'll still need the ggpofba.exe from the original GGPO, which will be launched through wine.

## Installation

Extract the original GGPO in ```/opt/ggpo```, and add ggpo.py and ggpofba.sh in the same folder.
Edit ggpo.py to set your username and password.

## Usage
<pre>
$ /opt/ggpo/ggpo.py
ggpo> /help
-!- available commands:
-!- /challenge &lt;nick&gt;	send a challenge request to &lt;nick&gt;
-!- /cancel    &lt;nick&gt;	cancel an ongoing challenge request to &lt;nick&gt;
-!- /accept    &lt;nick&gt;	accept a challenge request initiated by &lt;nick&gt;
-!- /decline   &lt;nick&gt;	decline a challenge request initiated by &lt;nick&gt;
-!- /watch     &lt;nick&gt;	watch the game that &lt;nick&gt; is currently playing
-!- /whois     &lt;nick&gt;	display information about the user &lt;nick&gt;
-!- /join   &lt;channel&gt;	join the chat/game room &lt;channel&gt;
-!- /list 		list all available channels or chat/game rooms
-!- /users (&lt;modifier&gt;)	list all users in the current channel
-!-          modifier: 'available', 'away' or 'playing'
-!- /intro 		view the channel welcome text
-!- /away 		set away status (you can't be challenged)
-!- /back 		set available status (you can be challenged)
-!- /clear 		clear the screen
-!- /quit 		quit ggpo
</pre>

## Screenshots
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-pof.png "ggpo screenshot 0")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py1.png "ggpo screenshot 1")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py2.png "ggpo screenshot 2")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py3.png "ggpo screenshot 3")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py4.png "ggpo screenshot 4")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py5.png "ggpo screenshot 5")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py6.png "ggpo screenshot 6")

