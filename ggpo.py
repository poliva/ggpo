#!/usr/bin/python
#
# command line ggpo client
# protocol reverse engineered from the official adobe air client
# 
#  (c) 2014 Pau Oliva Fora (@pof)
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#

import socket
import string
import sys
import time
import os
import struct
import readline
import termios
import fcntl
from subprocess import call
from threading import Thread

USERNAME="pof"
PASSWORD="XXXXXXXX"
CHANNEL="ssf2t"
FBA="/opt/ggpo/ggpofba.sh"

DEBUG=0 # values: 0,1,2

SPECIAL=""
OLDDATA=""

GRAY = '\033[0;30m'
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[0;33m'
BLUE = '\033[0;34m'
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'

B_GRAY = '\033[1;30m'
B_RED = '\033[1;31m'
B_GREEN = '\033[1;32m'
B_YELLOW = '\033[1;33m'
B_BLUE = '\033[1;34m'
B_MAGENTA = '\033[1;35m'
B_CYAN = '\033[1;36m'

END = '\033[0;m'

PROMPT = "\rggpo" + RED + "> " + END

def blank_current_readline():
	# thanks http://stackoverflow.com/questions/7907827/

	# Next line said to be reasonably portable for various Unixes
	(rows,cols) = struct.unpack('hh', fcntl.ioctl(sys.stdout, termios.TIOCGWINSZ,'1234'))

	text_len = len(readline.get_line_buffer())+2

	# ANSI escape sequences (All VT100 except ESC[0G)
	sys.stdout.write('\x1b[2K')                         # Clear current line
	sys.stdout.write('\x1b[1A\x1b[2K'*(text_len/cols))  # Move cursor up and clear line
	sys.stdout.write('\x1b[0G')                         # Move to start of line

def print_line(line):
	blank_current_readline()
	print line,
	sys.stdout.write(readline.get_line_buffer())
	sys.stdout.flush()

def readdata():
	global s
	try:
		foo = s.recv(4096)
		return foo
	except:
		return

def pad(value,length=4):
	l = len(value)
	while (l<length):
		value="\x00" + value
		l = len(value)
	return value

def parse(cmd):
	global SPECIAL

	pdulen = int(cmd[0:4].encode('hex'), 16)
	action = cmd[4:8]

	# chat
	if (action == "\xff\xff\xff\xfe"):
		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]
		msglen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
		msg = cmd[12+nicklen+4:pdulen+4]
		print "\r" + CYAN + "<" + str(nick) + "> " + END + str(msg)

	# state changes (away/available/playing)
	elif (action == "\xff\xff\xff\xfd"):

		unk1 = cmd[8:12]
		unk2 = cmd[12:16]

		nicklen = int(cmd[16:20].encode('hex'),16)
		nick = cmd[20:20+nicklen]


		if (unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x00"): print "\r" + GRAY + "-!- " + B_GRAY + str(nick) + GRAY +" has quit" + END

		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x00"):
		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x01"):
		#if (unk1 == "\x00\x00\x00\x04" and unk2 == "\x00\x00\x00\x01"): # match ended?
		#if (unk1 == "\x00\x00\x00\x05" and unk2 == "\x00\x00\x00\x01\):

		elif ((unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x01") or (unk1 == "\x00\x00\x00\x02" and unk2 == "\x00\x00\x00\x01")):

			state = int(cmd[20+nicklen:20+nicklen+4].encode('hex'),16)  # 1=away, 0=back, 2=play

			if (state==2):
				nick2len = int(cmd[24+nicklen:28+nicklen].encode('hex'),16)
				nick2 = cmd[28+nicklen:28+nicklen+nick2len]

				print "\r" + MAGENTA + "-!- new match " + B_MAGENTA + str(nick) + MAGENTA + " vs " + B_MAGENTA + str(nick2) + END

			elif (state <2):
				unk4 = cmd[20+nicklen+4:20+nicklen+8]

				iplen = int(cmd[20+nicklen+8:20+nicklen+12].encode('hex'),16)
				ip = cmd[32+nicklen:32+nicklen+iplen]

				unk6 = cmd[32+nicklen+iplen:32+nicklen+iplen+4]
				unk7 = cmd[36+nicklen+iplen:36+nicklen+iplen+4]

				citylen = int(cmd[40+nicklen+iplen:44+nicklen+iplen].encode('hex'),16)
				city = cmd[44+nicklen+iplen:44+nicklen+iplen+citylen]

				cclen = int(cmd[44+nicklen+iplen+citylen:48+nicklen+iplen+citylen].encode('hex'),16)
				cc = cmd[48+nicklen+iplen+citylen:48+nicklen+iplen+citylen+cclen]

				countrylen = int(cmd[48+nicklen+iplen+citylen+cclen:48+nicklen+iplen+citylen+cclen+4].encode('hex'),16)
				country = cmd[52+nicklen+iplen+citylen+cclen:52+nicklen+iplen+citylen+cclen+countrylen]

				print "\r" + GRAY + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip),
				if (city != "" and cc != ""): print "(" + city + ", " + cc + ")",
				elif (city == "" and cc != ""): print "(" + cc + ")",
				if (state == 0): print "is available",
				if (state == 1): print "is away",
				print END

		else:
			if (DEBUG>0): print "\r" + BLUE + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END

	# challenge request declined by peer
	elif (action == "\xff\xff\xff\xfb"):
		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]
		print "\r" + RED + "-!- " + B_RED + str(nick) + RED + " declined the challenge request"


	# challenge
	elif (action == "\xff\xff\xff\xfc"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		channellen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
		channel = cmd[16+nicklen:16+nicklen+channellen]

		print "\r" + RED + "-!- INCOMING CHALLENGE REQUEST FROM " + B_RED + str(nick) + RED + " @ " + channel + END
		print RED + "-!- TYPE '/accept " + B_RED + str(nick) + RED + "' to accept it, or '/decline " + B_RED + str(nick) + RED + "' to wimp out." + END

		args = ['mplayer', '/opt/ggpo/assets/challenger-comes.mp3']
		FNULL = open(os.devnull, 'w')
		call(args, stdout=FNULL, stderr=FNULL)
		FNULL.close()


	# cancel challenge
	elif (action == "\xff\xff\xff\xef"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		print "\r" + YELLOW + "-!- CHALLENGE REQUEST CANCELED BY " + B_YELLOW + str(nick) + END


	elif (action == "\xff\xff\xff\xff"):
		print "\r" + GRAY + "-!- Connection established" + END

	elif (action == "\x00\x00\x00\x02"):
		result = cmd[8:12]
		if (result == "\x00\x00\x00\x06"):
			print "\r" + RED + "-!- User or password incorrect" + END
			sys.exit(0)

	# watch
	elif (action == "\xff\xff\xff\xfa"):

		nick1len = int(cmd[8:12].encode('hex'),16)
		nick1 = cmd[12:12+nick1len]
		nick2len = int(cmd[12+nick1len:16+nick1len].encode('hex'),16)
		nick2 = cmd[16+nick1len:16+nick1len+nick2len]

		print "\r" + GREEN + "-!- watch " + B_GREEN + str(nick1) + GREEN + " vs " + B_GREEN + str(nick2) + END

		quark = cmd[20+nick1len+nick2len:pdulen+4]
		args = [FBA, quark]
		FNULL = open(os.devnull, 'w')
		call(args, stdout=FNULL, stderr=FNULL)
		FNULL.close()

	# unknown action
	else:
		if (SPECIAL == "" ):
			if (DEBUG>0): print "\r" + BLUE + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END
			#if (cmd[8:pdulen+4]=="\x00\x00\x00\x00" and int(action.encode('hex'),16)>4): print "ggpo> ",
		else:
			parsespecial(cmd)

	#print ("PDULEN: " + str(pdulen) + " ACTION: " + str(action))
	#print ("PDULEN: " + str(pdulen) + " CMDLEN: " + str(len(cmd)))
	if ( len(cmd) > pdulen+4 ): 
		parse(cmd[pdulen+4:])
		

def parsespecial(cmd):
	global SPECIAL

	pdulen = int(cmd[0:4].encode('hex'), 16)
	#myseqnum = int(cmd[4:8].encode('hex'),16)

	if (SPECIAL=="INTRO"):
		channellen = int(cmd[12:12+4].encode('hex'),16)
		channel = cmd[16:16+channellen]

		topiclen = int(cmd[16+channellen:20+channellen].encode('hex'),16)
		topic = cmd[20+channellen:20+channellen+topiclen]

		msglen = int(cmd[20+channellen+topiclen:24+channellen+topiclen].encode('hex'),16)
		msg = cmd[24+channellen+topiclen:24+channellen+topiclen+msglen]

		print "\r" + "\n" + B_GREEN + str(channel) + GREEN + " || " + B_GREEN + str(topic) + GREEN
		print str(msg) + END
		SPECIAL=""

	elif (SPECIAL=="AWAY"):
		SPECIAL=""

	elif (SPECIAL=="BACK"):
		SPECIAL=""

	elif (SPECIAL=="LIST"):
		SPECIAL=""
		parselist(cmd)

	elif (SPECIAL=="USERS"):
		SPECIAL=""
		parseusers(cmd)

	else:
		if (DEBUG>0): print "\r" + BLUE + "SPECIAL=" + SPECIAL + " + DATA: " + repr(cmd[8:pdulen+4]) + END

def parseusers(cmd):

	global SPECIAL, OLDDATA
	pdulen = int(cmd[0:4].encode('hex'), 16)

	## ugly workaround for when the user list is splitted in 2 PDUs
	#print "PDULEN: " + str(pdulen) + " CMDLEN: " + str(len(cmd))
	if (len(cmd)!=pdulen+4 and OLDDATA==""):
		SPECIAL="USERS"
		OLDDATA=cmd
		return

	if (OLDDATA!=""):
		cmd = OLDDATA + cmd
		pdulen = int(cmd[0:4].encode('hex'), 16)
		OLDDATA=""
		SPECIAL=""
	## end of workaround

	print "\r" + YELLOW + "-!- user list:" + END

	i=16
	while (i<pdulen):
	#while (i<len(cmd)-4):

		len1 = int(cmd[i:i+4].encode('hex'),16)
		i=i+4
		nick = cmd[i:i+len1]
		i=i+len1

		status = int(cmd[i:i+4].encode('hex'),16)  # 1=away, 2=playing, 0=available?
		i=i+4

		p2len = int(cmd[i:i+4].encode('hex'),16)  # should be 0 when not playing
		i=i+4

		if (p2len > 0):
			p2nick = cmd[i:i+p2len]
			i=i+p2len
		else:
			p2nick="None"

		iplen = int(cmd[i:i+4].encode('hex'),16)
		i=i+4

		ip = cmd[i:i+iplen]
		i=i+iplen

		unk1 = cmd[i:i+4]
		i=i+4

		unk2 = cmd[i:i+4]
		i=i+4

		citylen = int(cmd[i:i+4].encode('hex'),16)
		i=i+4

		city = cmd[i:i+citylen]
		i=i+citylen

		cclen = int(cmd[i:i+4].encode('hex'),16)
		i=i+4

		cc = cmd[i:i+cclen]
		i=i+cclen

		countrylen = int(cmd[i:i+4].encode('hex'),16)
		i=i+4

		country = cmd[i:i+countrylen]
		i=i+countrylen

		port = int(cmd[i:i+4].encode('hex'),16)
		i=i+4

		print YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip),
		if (city != "" and cc != ""): print "(" + city + ", " + cc + ")",
		elif (city == "" and cc != ""): print "(" + cc + ")",
		if (status == 0): print "is available",
		if (status == 1): print "is away",
		if (status == 2): print "is playing against " + B_GRAY + p2nick,
		print END

	print YELLOW + "-!- EOF user list." + END


def parselist(cmd):

	global SPECIAL, OLDDATA
	pdulen = int(cmd[0:4].encode('hex'), 16)

	## ugly workaround for when the channel list is splitted in 2 PDUs
	#print "PDULEN: " + str(pdulen) + " CMDLEN: " + str(len(cmd))
	if (len(cmd)!=pdulen+4 and OLDDATA==""):
		SPECIAL="LIST"
		OLDDATA=cmd
		return

	if (OLDDATA!=""):
		cmd = OLDDATA + cmd
		pdulen = int(cmd[0:4].encode('hex'), 16)
		OLDDATA=""
		SPECIAL=""
	## end of workaround

	print "\r" + YELLOW + "-!- channel list:" + END

	i=12
	while (i<pdulen):
	#while (i<len(cmd)-4):
		#num = int(cmd[i:i+4].encode('hex'),16)
		i=i+4
		len1 = int(cmd[i:i+4].encode('hex'),16)
		i=i+4
		name1 = cmd[i:i+len1]
		i=i+len1
		len2 = int(cmd[i:i+4].encode('hex'),16)
		i=i+4
		name2 = cmd[i:i+len2]
		i=i+len2
		len3 = int(cmd[i:i+4].encode('hex'),16)
		i=i+4
		name3 = cmd[i:i+len3]
		i=i+len3
		print YELLOW + "-!- " + B_GRAY +  str(name1) + GRAY + " (" + str(name2) + ") -- " + str(name3)

	print YELLOW + "-!- EOF channel list." + END

def pingcheck():
	global u

	while 1:
		dgram, addr = u.recvfrom(64)
		if (DEBUG>0): print "\r" + GRAY + "-!- UDP msg: " + dgram + " from " + str(addr) + END
		if (dgram[0:9] == "GGPO PING"):
			val = dgram[10:]
			u.sendto("GGPO PONG " + val, addr)
			if (DEBUG>0): print GRAY + "-!- UDP rpl: GGPO PONG " + val + " to " + str(addr) + END


def mainloop():
	global line,sequence,SPECIAL

	processed=0

	while 1:

		print_line(PROMPT)
		time.sleep(1)

		if (processed==1):
			line=""
			processed=0

		if (line != ""):
			processed=1

		if (line != None and line != "" and not line.startswith("/")):
			#print line
			msglen = len(line)
			pdulen = 4 + 4 + 4 + msglen
			# [ 4-byte pdulen ] [ 4-byte sequence ] [ 4-byte command ] [ 4-byte msglen ] [ msglen-bytes msg ]
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x07" + pad(chr(msglen)) + line)
			sequence=sequence+1

		# send a challenge request
		if (line != None and line.startswith("/challenge ")):
			nick = line[11:]
			nicklen = len(nick)
			channellen = len(CHANNEL)
			pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x08" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
			sequence=sequence+1
			print "\r" + GREEN + "-!- challenge request sent to " + B_GREEN + str(nick) + END
			print GREEN + "-!- type '/cancel " + B_GREEN + str(nick) + GREEN + "' to cancel it" + END

		# accept a challenge request (initiated by peer)
		if (line != None and line.startswith("/accept ")):
			nick = line[8:]
			nicklen = len(nick)
			channellen = len(CHANNEL)
			pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x09" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
			sequence=sequence+1
			print "\r" + GREEN + "-!- accepted challenge request from " + B_GREEN + str(nick) + END

		# decline a challenge request (initiated by peer)
		if (line != None and line.startswith("/decline ")):
			nick = line[9:]
			nicklen = len(nick)
			pdulen = 4 + 4 + 4 + nicklen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x0a" + pad(chr(nicklen)) + nick )
			sequence=sequence+1
			print "\r" + YELLOW + "-!- declined challenge request from " + B_YELLOW + str(nick) + END

		# cancel an ongoing challenge request (initiated by us)
		if (line != None and line.startswith("/cancel ")):
			nick = line[8:]
			nicklen = len(nick)
			pdulen = 4 + 4 + 4 + nicklen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x1c" + pad(chr(nicklen)) + nick )
			sequence=sequence+1
			print "\r" + YELLOW + "-!- canceled challenge request to " + B_YELLOW + str(nick) + END

		# watch an ongoing match
		if (line != None and line.startswith("/watch ")):
			nick = line[7:]
			nicklen = len(nick)
			pdulen = 4 + 4 + 4 + nicklen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x10" + pad(chr(nicklen)) + nick )
			sequence=sequence+1
			#print "\r" + GREEN + "-!- watch challenge from " + B_GREEN + str(nick) + END

		# choose channel
		if (line != None and line.startswith("/join ")):
			CHANNEL = line[6:]
			channellen = len(CHANNEL)
			pdulen = 4 + 4 + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x05" + pad(chr(channellen)) + CHANNEL )
			sequence=sequence+1

		# set away status (can't be challenged)
		if (line == "/away"):
			pdulen = 4+4+4
			SPECIAL="AWAY"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x01')
			sequence=sequence+1
			#print "\r" + GREEN + "-!- you are away now" + END

		# return back from away (can be challenged)
		if (line == "/back" or line == "/available"):
			pdulen = 4+4+4
			SPECIAL="BACK"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x00')
			sequence=sequence+1
			#print "\r" + GREEN + "-!- you are available now" + END

		# view channel intro
		if (line == "/intro"):
			pdulen = 4+4
			SPECIAL="INTRO"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x02')
			sequence=sequence+1

		# list channels
		if (line == "/list"):
			pdulen = 4+4
			SPECIAL="LIST"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x03')
			sequence=sequence+1

		# list users
		if (line == "/users" or line == "/who"):
			pdulen = 4+4
			SPECIAL="USERS"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x04')
			sequence=sequence+1

		if (DEBUG>1):
			print "\r" + BLUE + "HEX: ",repr(data) + END



def datathread():
	global data
	while 1:
		data = readdata()
		parse(data)
		print_line(PROMPT)
		time.sleep(2)

if __name__ == '__main__':

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('ggpo.net', 7000))

	u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
	u.bind(('0.0.0.0', 6009))

	t = Thread(target=pingcheck)
	t.daemon = True
	t.start()

	# welcome packet (?)
	s.send('\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x01')

	# authentication
	sequence=0x2
	pdulen = 4 + 4 + 4 + len(USERNAME) + 4 + len (PASSWORD) + 4
	s.send( pad(chr(pdulen)) + "\x00\x00\x00\x02" + "\x00\x00\x00\x01" + pad(chr(len(USERNAME))) + USERNAME + pad(chr(len(PASSWORD))) + PASSWORD + "\x00\x00\x17\x79")
	sequence=sequence+1

	# choose channel
	channellen = len(CHANNEL)
	pdulen = 4 + 4 + 4 + channellen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x05" + pad(chr(channellen)) + CHANNEL )
	sequence=sequence+1

	# start away by default
	s.send( pad(chr(12)) + pad(chr(sequence)) + "\x00\x00\x00\x06" + "\x00\x00\x00\x01")
	sequence=sequence+1

	#print PROMPT,

	t2 = Thread(target=mainloop)
	t2.daemon = False
	t2.start()

	t3 = Thread(target=datathread)
	t3.daemon = False
	t3.start()

	line=""

	while 1:
		line = raw_input()

		if (line == "/help"):
			print "\r" + BLUE + "-!- available commands:" + END
			print BLUE + "-!- /challenge <nick>\tsend a challenge request to <nick>" + END
			print BLUE + "-!- /cancel    <nick>\tcancel an ongoing challenge request to <nick>" + END
			print BLUE + "-!- /accept    <nick>\taccept a challenge request initiated by <nick>" + END
			print BLUE + "-!- /decline   <nick>\tdecline a challenge request initiated by <nick>" + END
			print BLUE + "-!- /watch     <nick>\twatch the game that <nick> is currently playing" + END
			print BLUE + "-!- /join   <channel>\tjoin the chat/game room <channel>" + END
			print BLUE + "-!- /list \t\tlist all available channels or chat/game rooms" + END
			print BLUE + "-!- /users \t\tlist all users in the current channel" + END
			print BLUE + "-!- /intro \t\tview the channel welcome text" + END
			print BLUE + "-!- /away \t\tset away status (you can't be challenged)" + END
			print BLUE + "-!- /back \t\tset available status (you can be challenged)" + END
			print BLUE + "-!- /clear \t\tclear the screen" + END
			print BLUE + "-!- /quit \t\tquit ggpo" + END

		if (line == "/clear"):
			call(['clear'])

		if (line == "/quit"):
			print "\r" + BLUE + "-!- have a nice day :)" + END
			s.close()
			u.close()
			os._exit(0)

	s.close()
