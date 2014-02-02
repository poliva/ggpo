ggpo
====

&copy;2014 Pau Oliva Fora ([@pof](https://twitter.com/pof))

This is an alternative [GGPO](http://ggpo.net/) command line client written in python.
This allows you to play GGPO on Linux and MacOS X systems.
You'll still need the ggpofba.exe from the original GGPO, which will be launched through wine.

## Installation

Extract the original GGPO in ```/opt/ggpo```, and add ggpo.py and ggpofba.sh in the same folder.
Edit ggpo.py to set your username and password.

### Linux
1. Make sure you have [wine](http://www.winehq.org/) installed on your distribution (usually ```apt-get install wine``` on debian based systems)
2. run 'winecfg' and check the option to "Emulate a virtual desktop"

### Mac
1. Download the latest wine in the "[Wine.app Downloads](http://winebottler.kronenberg.org/downloads)" section (you do not need to download WineBottler). Note: You can easily close the sponsor ad after 5 seconds
2. Run Wine.dmg and drag the wine icon to your Applications folder

## Usage
Just execute ggpo.py:
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
-!- /whowas    &lt;nick&gt;	information about &lt;nick&gt; that is no longer connected
-!- /join   &lt;channel&gt;	join the chat/game room &lt;channel&gt;
-!- /list 		list all available channels or chat/game rooms
-!- /users (&lt;modifier&gt;)	list all users in the current channel
-!-          modifier: 'available', 'away' or 'playing'
-!- /intro 		view the channel welcome text
-!- /away 		set away status (you can't be challenged)
-!- /back 		set available status (you can be challenged)
-!- /clear 		clear the screen
-!- /quit 		disconnect from ggpo server
</pre>

## Screenshots
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-pof.png "ggpo screenshot 0")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py1.png "ggpo screenshot 1")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py2.png "ggpo screenshot 2")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py3.png "ggpo screenshot 3")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py4.png "ggpo screenshot 4")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py5.png "ggpo screenshot 5")
![alt text](https://github.com/poliva/ggpo/raw/master/img/ggpo-py6.png "ggpo screenshot 6")

