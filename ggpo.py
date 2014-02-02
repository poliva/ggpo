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
import datetime
import os
import struct
import readline
import termios
import fcntl
from subprocess import call
from threading import Thread
from random import randint
from operator import itemgetter

USERNAME="pof"
PASSWORD="XXXXXXXX"
CHANNEL="ssf2t"
FBA="/opt/ggpo/ggpofba.sh"

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

	text_len = len(readline.get_line_buffer().strip('\t\n\r'))+2

	# ANSI escape sequences (All VT100 except ESC[0G)
	sys.stdout.write('\x1b[2K')                         # Clear current line
	sys.stdout.write('\x1b[1A\x1b[2K'*(text_len/cols))  # Move cursor up and clear line
	sys.stdout.write('\x1b[0G')                         # Move to start of line

def print_line(text):
	blank_current_readline()
	linebuffer = readline.get_line_buffer()
	print text,
	if "\n" in linebuffer:
		sys.stdout.write(text)
	else:
		sys.stdout.write(linebuffer.strip('\t\n\r'))
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
	global SPECIAL,challengers,challenged,sequence

	pdulen = int(cmd[0:4].encode('hex'), 16)
	action = cmd[4:8]

	# chat
	if (action == "\xff\xff\xff\xfe"):
		if (VERBOSE>0):
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


		if (unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x00"):
			if (VERBOSE>2): print "\r" + GRAY + "-!- " + B_GRAY + str(nick) + GRAY +" has quit" + END

		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x00"):
		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x01"):
		#if (unk1 == "\x00\x00\x00\x04" and unk2 == "\x00\x00\x00\x01"): # match ended?
		#if (unk1 == "\x00\x00\x00\x05" and unk2 == "\x00\x00\x00\x01\):

		elif ((unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x01") or (unk1 == "\x00\x00\x00\x02" and unk2 == "\x00\x00\x00\x01")):

			state = int(cmd[20+nicklen:20+nicklen+4].encode('hex'),16)  # 1=away, 0=back, 2=play

			if (state==2):
				if (VERBOSE>1):
					nick2len = int(cmd[24+nicklen:28+nicklen].encode('hex'),16)
					nick2 = cmd[28+nicklen:28+nicklen+nick2len]
					print "\r" + MAGENTA + "-!- new match " + B_MAGENTA + str(nick) + MAGENTA + " vs " + B_MAGENTA + str(nick2) + END
					# remove from challenged set when nick2 accepts our challenge
					if (nick==USERNAME and nick2 in list(challenged)): challenged.remove(nick2)

			elif (state <2):
				if (VERBOSE>2):
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
		if nick in list(challenged): challenged.remove(nick)
		print "\r" + RED + "-!- " + B_RED + str(nick) + RED + " declined the challenge request"


	# challenge
	elif (action == "\xff\xff\xff\xfc"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		channellen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
		channel = cmd[16+nicklen:16+nicklen+channellen]

		print "\r" + RED + "-!- INCOMING CHALLENGE REQUEST FROM " + B_RED + str(nick) + RED + " @ " + channel + END
		print RED + "-!- TYPE '/accept " + B_RED + str(nick) + RED + "' to accept it, or '/decline " + B_RED + str(nick) + RED + "' to wimp out." + END

		challengers.add(nick)

		args = ['mplayer', '/opt/ggpo/assets/challenger-comes.mp3']
		try:
			FNULL = open(os.devnull, 'w')
			call(args, stdout=FNULL, stderr=FNULL)
			FNULL.close()
		except OSError:
			pass


	# cancel challenge
	elif (action == "\xff\xff\xff\xef"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]
		if nick in list(challengers): challengers.remove(nick)
		print "\r" + YELLOW + "-!- CHALLENGE REQUEST CANCELED BY " + B_YELLOW + str(nick) + END


	elif (action == "\xff\xff\xff\xff"):
		print "\r" + GRAY + "-!- Connection established" + END
		pdulen = 4+4
		SPECIAL="INTRO"
		s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x02')
		sequence=sequence+1


	elif (action == "\x00\x00\x00\x02"):
		result = cmd[8:12]
		if (result == "\x00\x00\x00\x06"):
			s.close()
			u.close()
			call(['reset'])
			print "\r" + RED + "-!- User or password incorrect" + END
			os._exit(0)

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
		try:
			channellen = int(cmd[12:12+4].encode('hex'),16)
			channel = cmd[16:16+channellen]

			topiclen = int(cmd[16+channellen:20+channellen].encode('hex'),16)
			topic = cmd[20+channellen:20+channellen+topiclen]

			msglen = int(cmd[20+channellen+topiclen:24+channellen+topiclen].encode('hex'),16)
			msg = cmd[24+channellen+topiclen:24+channellen+topiclen+msglen]

			print "\r" + B_GREEN + str(channel) + GREEN + " || " + B_GREEN + str(topic) + GREEN
			print str(msg) + END
		except ValueError:
			pass
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

def check_ping(nick,ip,port):
	global pinglist

	num1 = randint(500000,30000000)
	num2 = randint(4000000,900000000)
	message = "GGPO PING " + str(num1) + " " + str(num2)
	u.sendto(message, (ip, port))
	mytime = time.time()
	found=0
	for i in range( len( pinglist ) ):
		if (pinglist[i][1]==nick and pinglist[i][2]==ip):
			pinglist[i][0]=mytime
			pinglist[i][4]=str(num1)+" "+str(num2)
			found=1
			break
	if (found==0):
		# last digit used to store the ping value in msec
		pingquery=[mytime,nick,ip,port,str(num1)+" "+str(num2),0]
		pinglist.append(pingquery)

def get_ping_msec(nick,ip):
	for i in range( len( pinglist ) ):
		if (pinglist[i][1]==nick and pinglist[i][2]==ip):
			ping = pinglist[i][5]
			break
	return ping

def parseusers(cmd):

	global SPECIAL, OLDDATA, userlist
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

	userlist=[]

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
			p2nick="null"

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

		check_ping(nick,ip,port)
		user = [nick,ip,city,cc,country,port,status,p2nick,0]
		userlist.append(user)

	# sleep 1sec to collect ping data
	time.sleep(1)

	# create 3 lists
	available_users=[]
	away_users=[]
	playing_users=[]

	for user in userlist:
		nick=user[0]
		ip=user[1]
		user[8]=get_ping_msec(nick,ip)
		# put the users on each list
		status=user[6]
		if (status == 0): available_users.append(user)
		elif (status == 1): away_users.append(user)
		elif (status == 2): playing_users.append(user)

	# sort userlist by ping value
	userlist = sorted(userlist, key=itemgetter(8), reverse=False)
	available_users = sorted(available_users, key=itemgetter(8), reverse=False)
	away_users = sorted(away_users, key=itemgetter(8), reverse=False)
	playing_users = sorted(playing_users, key=itemgetter(8), reverse=False)

	if (users_option.startswith("/whois ")):
		query=users_option[7:]

		found = print_user_long(query,"whois")
		if (found == 1):
			print "\r" + YELLOW + "-!- " + GRAY + "End of WHOIS" + END
		else:
			print "\r" + YELLOW + "-!- There is no such nick " + B_YELLOW + query + END

	elif (users_option.startswith("/users ")):
		subcmd=users_option[7:]

		print "\r" + YELLOW + "-!- user list:" + END
		if (subcmd == "available"):
			for user in available_users: print_user(user)
		elif (subcmd=="away"):
			for user in away_users: print_user(user)
		elif (subcmd=="playing"):
			for user in playing_users: print_user(user)
		else:
			print "\r" + YELLOW + "-!- possible modifiers are: available, away, playing" + END

		print "\r" + YELLOW + "-!- EOF user list." + END

	else:
		print "\r" + YELLOW + "-!- user list:" + END
		for user in available_users: print_user(user)
		for user in playing_users: print_user(user)
		for user in away_users: print_user(user)
		print "\r" + YELLOW + "-!- EOF user list." + END

def print_user_long(nick,command):

	# initalize values
	found=0
	ping=0
	lastseen=""
	ip=""
	port=""
	city=""
	cc=""
	country=""
	status=""
	p2nick=""

	for i in range( len( pinglist ) ):
		if (pinglist[i][1]==nick):
			lastseen = pinglist[i][0]
			ip = pinglist[i][2]
			port = pinglist[i][3]
			ping = pinglist[i][5]
			found=1
			break
	for i in range(len(userlist)):
		if (userlist[i][0]==nick):
			ip = userlist[i][1]
			city = userlist[i][2]
			cc = userlist[i][3]
			country = userlist[i][4]
			port = userlist[i][5]
			status = userlist[i][6]
			p2nick = userlist[i][7]
			if (ping==0): ping = userlist[i][8]
			found=1
			break

	if (found==0): return 0

	try:
		hostname = socket.gethostbyaddr(ip)
	except socket.herror:
		hostname = (ip,ip,ip)

	print "\r" + YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip) + ":" + str(port) + END
	if (command == "whois"): print "\r" + YELLOW + "-!- " + GRAY + "  channel  : " + CHANNEL + END
	print "\r" + YELLOW + "-!- " + GRAY + "  hostname : " + hostname[0] + END
	if (lastseen != ""): print "\r" + YELLOW + "-!- " + GRAY + "  lastseen : " + datetime.datetime.fromtimestamp(int(lastseen)).strftime('%Y-%m-%d %H:%M:%S') + END
	print "\r" + YELLOW + "-!- " + GRAY + "  location :",
	if (city != "" and cc != ""): print city + ", " + cc + ", " + country
	elif (city == "" and cc != ""): print cc + ", " + country
	else: print "unknown"
	print "\r" + YELLOW + "-!- " + GRAY + "  status   :",
	if (status == 0): print "available"
	if (status == 1): print "away"
	if (status == 2): print "playing against " + B_GRAY + p2nick
	if (ping != 0): print "\r" + YELLOW + "-!- " + GRAY + "  ping     : " + str(int(ping)) + " ms" + END
	if nick in challenged:
		print "\r" + YELLOW + "-!- " + GRAY + " you have challenged " + B_GRAY + str(nick) + END
	if nick in challengers:
		print "\r" + YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + " has challenged you" + END
	return 1

def print_user(user):

	nick=user[0]
	ip=user[1]
	city=user[2]
	cc=user[3]
	country=user[4]
	port=user[5]
	status=user[6]
	p2nick=user[7]
	ping=user[8]

	if (ping==0): ping = get_ping_msec(nick,ip)
	print "\r" + YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip),
	if (city != "" and cc != ""): print "(" + city + ", " + cc + ")",
	elif (city == "" and cc != ""): print "(" + cc + ")",
	if (status == 0): print "is available",
	if (status == 1): print "is away",
	if (status == 2): print "is playing against " + B_GRAY + p2nick,
	if (ping != 0): print GRAY + "[" + str(int(ping)) + " ms]",
	if nick in challenged:
		print GREEN + "*challenged",
	if nick in challengers:
		print RED + "*challenging",

	print END

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
	global u, pinglist

	while 1:
		dgram, addr = u.recvfrom(64)
		if (DEBUG>0): print "\r" + GRAY + "-!- UDP msg: " + dgram + " from " + str(addr) + END
		if (dgram[0:9] == "GGPO PING"):
			val = dgram[10:]
			u.sendto("GGPO PONG " + val, addr)
			if (DEBUG>0): print GRAY + "-!- UDP rpl: GGPO PONG " + val + " to " + str(addr) + END
		if (dgram[0:9] == "GGPO PONG"):
			mytime = time.time()
			val = dgram[10:]
			for i in range( len( pinglist ) ):
				if (pinglist[i][4]==val and pinglist[i][2]==addr[0]):
					msec = (mytime-pinglist[i][0])*1000
					pinglist[i][5]=msec
					break
def pdu_accept(nick):
	global sequence,challengers

	nicklen = len(nick)
	channellen = len(CHANNEL)
	pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x09" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
	sequence=sequence+1
	print "\r" + GREEN + "-!- accepted challenge request from " + B_GREEN + str(nick) + END
	challengers.remove(nick)

def pdu_decline(nick):
	global sequence, challengers

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x0a" + pad(chr(nicklen)) + nick )
	sequence=sequence+1
	print "\r" + YELLOW + "-!- declined challenge request from " + B_YELLOW + str(nick) + END
	challengers.remove(nick)

def pdu_cancel(nick):
	global sequence,challenged

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x1c" + pad(chr(nicklen)) + nick )
	sequence=sequence+1
	print "\r" + YELLOW + "-!- canceled challenge request to " + B_YELLOW + str(nick) + END
	challenged.remove(nick)

def mainloop():
	global line,sequence,SPECIAL,challengers,challenged,CHANNEL,users_option

	processed=0
	olddata=""

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
			challenged.add(nick)
			print "\r" + GREEN + "-!- challenge request sent to " + B_GREEN + str(nick) + END
			print GREEN + "-!- type '/cancel " + B_GREEN + str(nick) + GREEN + "' to cancel it" + END

		# accept a challenge request (initiated by peer)
		if (line != None and line.startswith("/accept ")):
			nick = line[8:]
			if nick in list(challengers):
				pdu_accept(nick)
			else:
				print "\r" + YELLOW + "-!- " + B_YELLOW + str(nick) + YELLOW + " hasn't challenged you" + END

		# if there's only one incoming challenge request, allow the user to type /accept without parameters (no need to specify nick)
		if (line == "/accept"):
			if (len(challengers)==1):
				for nick in list(challengers):
					pdu_accept(nick)
					break
			else:
				print "\r" + YELLOW + "-!- " + "There's more than one incoming challenge request: you need to specify the nick." + END

		# decline a challenge request (initiated by peer)
		if (line != None and line.startswith("/decline ")):
			nick = line[9:]
			if nick in list(challengers):
				pdu_decline(nick)
			else:
				print "\r" + YELLOW + "-!- " + B_YELLOW + str(nick) + YELLOW + " hasn't challenged you" + END

		# /decline without parameters declines all incoming challenge requests
		if (line == "/decline"):
			for nick in list(challengers):
				pdu_decline(nick)

		# cancel an ongoing challenge request (initiated by us)
		if (line != None and line.startswith("/cancel ")):
			nick = line[8:]
			if nick in list(challenged):
				pdu_cancel(nick)
			else:
				print "\r" + YELLOW + "-!- you aren't challenging " + B_YELLOW + str(nick) + END

		# /cancel without parameters: cancel all ongoing challenge requests
		if (line == "/cancel"):
			for nick in list(challenged):
				pdu_cancel(nick)

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
		if (line != None and ( line.startswith("/users") or line.startswith("/whois ") or line=="/who" )):
			users_option=line
			pdulen = 4+4
			SPECIAL="USERS"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x04')
			sequence=sequence+1

		if (DEBUG>1 and olddata!=data):
			print "\r" + BLUE + "HEX: ",repr(data) + END
			olddata=data



def datathread():
	global data
	while 1:
		data = readdata()
		parse(data)
		print_line(PROMPT)
		time.sleep(2)

def showverbose():
	print "\r" + YELLOW + "-!- " + GRAY + "current VERBOSE=" + B_GRAY + str(VERBOSE) + GRAY,
	if (VERBOSE==0): print "only showing challenge requests/replies" + END
	if (VERBOSE==1): print "showing challenges + chat" + END
	elif (VERBOSE==2): print "showing challenges + chat + new matches" + END
	elif (VERBOSE==3): print "showing challenges + chat + new matches + status changes" + END

if __name__ == '__main__':

	DEBUG=0 # values: 0,1,2
	VERBOSE=3 # values: 0,1,2,3

	SPECIAL=""
	OLDDATA=""

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

	t2 = Thread(target=datathread)
	t2.daemon = False
	t2.start()

	t3 = Thread(target=mainloop)
	t3.daemon = False
	t3.start()

	line=""
	challengers=set()
	challenged=set()
	users_option=""
	pinglist=[]
	userlist=[]

	while 1:
		line = raw_input()
		line = line.strip(' \t\n\r')

		if (line == "/help"):
			print "\r" + BLUE + "-!- available commands:" + END
			print "\r" + BLUE + "-!- /challenge [<nick>]\tsend a challenge request to <nick>" + END
			print "\r" + BLUE + "-!- /cancel    [<nick>]\tcancel an ongoing challenge request to <nick>" + END
			print "\r" + BLUE + "-!- /accept    [<nick>]\taccept a challenge request initiated by <nick>" + END
			print "\r" + BLUE + "-!- /decline   [<nick>]\tdecline a challenge request initiated by <nick>" + END
			print "\r" + BLUE + "-!- /watch     <nick>\twatch the game that <nick> is currently playing" + END
			print "\r" + BLUE + "-!- /whois     <nick>\tdisplay information about the user <nick>" + END
			print "\r" + BLUE + "-!- /whowas    <nick>\tinfo about <nick> that is no longer connected" + END
			print "\r" + BLUE + "-!- /join   <channel>\tjoin the chat/game room <channel>" + END
			print "\r" + BLUE + "-!- /list \t\tlist all available channels or chat/game rooms" + END
			print "\r" + BLUE + "-!- /users [<modifier>]\tlist all users in the current channel" + END
			print "\r" + BLUE + "-!-          modifier: 'available', 'away' or 'playing'" + END
			print "\r" + BLUE + "-!- /intro \t\tview the channel welcome text" + END
			print "\r" + BLUE + "-!- /away \t\tset away status (you can't be challenged)" + END
			print "\r" + BLUE + "-!- /back \t\tset available status (you can be challenged)" + END
			print "\r" + BLUE + "-!- /clear \t\tclear the screen" + END
			print "\r" + BLUE + "-!- /verbose [<flag>]\tchange verbosity level" + END
			print "\r" + BLUE + "-!-            flag:'0' challenges, '1' chat, '2' match, '3' status" + END
			print "\r" + BLUE + "-!- /quit \t\tdisconnect from ggpo server" + END

		if (line.startswith("/whowas ")):
			nick = line[8:]
			found = print_user_long(nick,"whowas")
			if (found==1):
				print "\r" + YELLOW + "-!- " + GRAY + "End of WHOWAS" + END
			else:
				print "\r" + YELLOW + "-!- There was no such nick " + B_YELLOW + nick + END

		# hidden command, not present in /help
		if (line.startswith("/debug ")):
			debug = line[7:]
			if (debug == "0"): DEBUG=0
			elif (debug == "1"): DEBUG=1
			elif (debug == "2"): DEBUG=2
			else: print "\r" + YELLOW + "-!- possible values are /debug [<0|1|2>]" + END
		if (line == "/debug"):
			print "\r" + YELLOW + "-!- " + GRAY + "DEBUG: " + str(DEBUG) + END

		if (line.startswith("/verbose ")):
			verbose = line[9:]
			if (verbose == "0"): VERBOSE=0
			elif (verbose == "1"): VERBOSE=1
			elif (verbose == "2"): VERBOSE=2
			elif (verbose == "3"): VERBOSE=3
			else: print "\r" + YELLOW + "-!- possible values are /verbose [<0|1|2|3>]" + END
			showverbose()

		if (line == "/verbose"):
			showverbose()

		if (line == "/challenge"):
			print "\r" + YELLOW + "-!- " + GRAY + "challenging:",
			for nick in challenged:
				print "["+ B_GREEN + nick + GRAY + "]",
			print END

		if (line == "/clear"):
			call(['clear'])

		if (line == "/quit"):
			s.close()
			u.close()
			#call(['reset'])
			print "\r" + BLUE + "-!- have a nice day :)" + END
			os._exit(0)
