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
import urllib2
from Queue import Queue
from subprocess import call
from threading import Thread
from random import randint
from operator import itemgetter

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
VERSION = "1.0.3"

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

def pad(value,length=4):
	l = len(value)
	while (l<length):
		value="\x00" + value
		l = len(value)
	return value

def parse(cmd):
	global challengers,challenged,sequence

	if (len(cmd) < 8):
		return

	pdulen = int(cmd[0:4].encode('hex'), 16)
	action = cmd[4:8]

	# chat
	if (action == "\xff\xff\xff\xfe"):
		if (VERBOSE>0):
			nicklen = int(cmd[8:12].encode('hex'),16)
			nick = cmd[12:12+nicklen]
			msglen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
			msg = cmd[12+nicklen+4:pdulen+4]
			if (USERNAME+" " in msg or " "+USERNAME in msg or msg==USERNAME):
				args = ['notify-send', '--icon=' + INSTALLDIR + '/assets/icon-128.png', msg]
				try:
					FNULL = open(os.devnull, 'w')
					call(args, stdout=FNULL, stderr=FNULL)
					FNULL.close()
				except OSError:
					pass
				msg = msg.replace(USERNAME, B_YELLOW + USERNAME + END)

			print_line ( CYAN + "<" + str(nick) + "> " + END + str(msg) + "\n")

	# state changes (away/available/playing)
	elif (action == "\xff\xff\xff\xfd"):

		unk1 = cmd[8:12]
		unk2 = cmd[12:16]

		nicklen = int(cmd[16:20].encode('hex'),16)
		nick = cmd[20:20+nicklen]


		if (unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x00"):
			if (VERBOSE>2): print_line ( GRAY + "-!- " + B_GRAY + str(nick) + GRAY +" has quit" + END +"\n")

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
					if (nick2 == ""): nick2="null"
					print_line ( MAGENTA + "-!- new match " + B_MAGENTA + str(nick) + MAGENTA + " vs " + B_MAGENTA + str(nick2) + END +"\n" )
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

					text = GRAY + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip), 
					if (city != "" and cc != ""): text+= "(" + city + ", " + cc + ")",
					elif (city == "" and cc != ""): text+= "(" + cc + ")",
					if (state == 0): text+= "is available",
					if (state == 1): text+= "is away",
					text+=END+"\n",
					print_line(' '.join(text))

		else:
			if (DEBUG>0): print_line ( BLUE + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END +"\n")

	# challenge request declined by peer
	elif (action == "\xff\xff\xff\xfb"):
		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]
		if nick in list(challenged): challenged.remove(nick)
		print_line ( RED + "-!- " + B_RED + str(nick) + RED + " declined the challenge request" +"\n")


	# challenge
	elif (action == "\xff\xff\xff\xfc"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		channellen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
		channel = cmd[16+nicklen:16+nicklen+channellen]

		print_line ( RED + "-!- INCOMING CHALLENGE REQUEST FROM " + B_RED + str(nick) + RED + " @ " + channel + END +"\n" )
		print_line ( RED + "-!- TYPE '/accept " + B_RED + str(nick) + RED + "' to accept it, or '/decline " + B_RED + str(nick) + RED + "' to wimp out." + END +"\n")

		challengers.add(nick)

		args = ['mplayer', MP3]
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
		print_line ( YELLOW + "-!- CHALLENGE REQUEST CANCELED BY " + B_YELLOW + str(nick) + END + "\n")


	# joining a channel
	elif (action == "\xff\xff\xff\xff"):
		print_line ( GRAY + "-!- Connection established" + END + "\n")
		pdu_motd()

	# password incorrect (reply to request with sequence=2)
	elif (action == "\x00\x00\x00\x02"):
		result = cmd[8:12]
		if (result == "\x00\x00\x00\x06"):
			s.close()
			u.close()
			call(['reset'])
			print_line ( RED + "-!- Password incorrect" + END + "\n")
			print_line ( RED + "-!- Check config file at " + CONFIGFILE + END + "\n")
			os._exit(0)

	# reply to request with sequence=3
	elif (action == "\x00\x00\x00\x03"):
		result = cmd[8:12]
		# user incorrect
		if (result == "\x00\x00\x00\x04"):
			s.close()
			u.close()
			call(['reset'])
			print_line ( RED + "-!- User incorrect" + END + "\n")
			print_line ( RED + "-!- Check config file at " + CONFIGFILE + END + "\n")
			os._exit(0)

	# watch
	elif (action == "\xff\xff\xff\xfa"):

		nick1len = int(cmd[8:12].encode('hex'),16)
		nick1 = cmd[12:12+nick1len]
		nick2len = int(cmd[12+nick1len:16+nick1len].encode('hex'),16)
		nick2 = cmd[16+nick1len:16+nick1len+nick2len]

		print_line ( GREEN + "-!- watch " + B_GREEN + str(nick1) + GREEN + " vs " + B_GREEN + str(nick2) + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ggpofba.sh"):
			print_line ( YELLOW + "-!- WARNING: cannot find ggpofba.sh in " + INSTALLDIR + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ggpofba.exe"):
			print_line ( YELLOW + "-!- WARNING: cannot find ggpofba.exe in " + INSTALLDIR + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ROMs/" + CHANNEL + ".zip"):
			print_line ( YELLOW + "-!- WARNING: cannot find game ROM at " + INSTALLDIR + "/ROMs/" + CHANNEL + ".zip" + END + "\n")

		quark = cmd[20+nick1len+nick2len:pdulen+4]
		args = [FBA, quark]
		try:
			FNULL = open(os.devnull, 'w')
			call(args, stdout=FNULL, stderr=FNULL)
			FNULL.close()
		except OSError:
			print_line ( RED + "-!- ERROR: can't execute " + FBA + END + "\n")

	# unknown action
	else:
		if (SPECIAL == "" ):
			if (DEBUG>0): print_line ( BLUE + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END + "\n")
			#if (cmd[8:pdulen+4]=="\x00\x00\x00\x00" and int(action.encode('hex'),16)>4): print "ggpo> ",
		else:
			parsespecial(cmd)

	#print ("PDULEN: " + str(pdulen) + " ACTION: " + str(action))
	#print ("PDULEN: " + str(pdulen) + " CMDLEN: " + str(len(cmd)))
	if ( len(cmd) > pdulen+4 and len(cmd[pdulen+4:]) >=8 ):
		parse(cmd[pdulen+4:])
		

def parsespecial(cmd):
	global SPECIAL

	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
		#myseqnum = int(cmd[4:8].encode('hex'),16)
	except:
		pdulen = 0

	if (SPECIAL=="MOTD"):
		try:
			channellen = int(cmd[12:12+4].encode('hex'),16)
			channel = cmd[16:16+channellen]

			topiclen = int(cmd[16+channellen:20+channellen].encode('hex'),16)
			topic = cmd[20+channellen:20+channellen+topiclen]

			msglen = int(cmd[20+channellen+topiclen:24+channellen+topiclen].encode('hex'),16)
			msg = cmd[24+channellen+topiclen:24+channellen+topiclen+msglen]

			print_line ( B_GREEN + str(channel) + GREEN + " || " + B_GREEN + str(topic) + GREEN + "\n")
			print_line ( str(msg) + END + "\n")
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
		if (DEBUG>0): print_line ( BLUE + "SPECIAL=" + SPECIAL + " + DATA: " + repr(cmd[8:pdulen+4]) + END + "\n")

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
	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
	except:
		pdulen = 0

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

		try:
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
		except:
			if (DEBUG>0): print_line ( BLUE + "error parsing user " + str(nick) + END + "\n")
			#pass

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
			print_line ( YELLOW + "-!- " + GRAY + "End of WHOIS" + END + "\n")
		else:
			print_line ( YELLOW + "-!- There is no such nick " + B_YELLOW + query + END + "\n")

	elif (users_option.startswith("/users ")):
		subcmd=users_option[7:]

		print_line ( YELLOW + "-!- user list:" + END + "\n")
		if (subcmd == "available"):
			for user in available_users: print_user(user)
		elif (subcmd=="away"):
			for user in away_users: print_user(user)
		elif (subcmd=="playing"):
			for user in playing_users: print_user(user)
		else:
			print_line ( YELLOW + "-!- possible modifiers are: available, away, playing" + END + "\n")

		print_line ( YELLOW + "-!- EOF user list." + END + "\n")

	else:
		print_line ( YELLOW + "-!- user list:" + END + "\n")
		for user in available_users: print_user(user)
		for user in playing_users: print_user(user)
		for user in away_users: print_user(user)
		print_line ( YELLOW + "-!- EOF user list." + END + "\n")

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

	print_line ( YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip) + ":" + str(port) + END + "\n")
	if (command == "whois"): print_line ( YELLOW + "-!- " + GRAY + "  channel  : " + CHANNEL + END + "\n")
	print_line ( YELLOW + "-!- " + GRAY + "  hostname : " + hostname[0] + END + "\n")
	if (lastseen != ""): print_line ( YELLOW + "-!- " + GRAY + "  lastseen : " + datetime.datetime.fromtimestamp(int(lastseen)).strftime('%Y-%m-%d %H:%M:%S') + END + "\n")
	text = YELLOW + "-!- " + GRAY + "  location :",
	if (city != "" and cc != ""): text+= city + ", " + cc + ", " + country,
	elif (city == "" and cc != ""): text+= cc + ", " + country,
	else: text+= "unknown",
	text+=END+"\n",
	print_line (' '.join(text))
	text = YELLOW + "-!- " + GRAY + "  status   :",
	if (status == 0): text+= "available",
	if (status == 1): text+= "away",
	if (status == 2): text+= "playing against " + B_GRAY + p2nick,
	text+=END+"\n",
	print_line (' '.join(text))
	if (ping != 0): print_line ( YELLOW + "-!- " + GRAY + "  ping     : " + str(int(ping)) + " ms" + END + "\n")
	if nick in challenged:
		print_line ( YELLOW + "-!- " + GRAY + " you have challenged " + B_GRAY + str(nick) + END + "\n")
	if nick in challengers:
		print_line ( YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + " has challenged you" + END + "\n")
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
	text = YELLOW + "-!- " + B_GRAY + str(nick) + GRAY + "@" + str(ip),
	if (city != "" and cc != ""): text+= "(" + city + ", " + cc + ")",
	elif (city == "" and cc != ""): text+= "(" + cc + ")",
	if (status == 0): text+= "is available",
	if (status == 1): text+= "is away",
	if (status == 2): text+= "is playing against " + B_GRAY + p2nick,
	if (ping != 0): text+= GRAY + "[" + str(int(ping)) + " ms]",
	if nick in challenged:
		text+= GREEN + "*challenged",
	if nick in challengers:
		text+= RED + "*challenging",
	text+=END+"\n",
	print_line(' '.join(text))

def parselist(cmd):

	global SPECIAL, OLDDATA

	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
	except:
		pdulen = 0

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

	print_line ( YELLOW + "-!- channel list:" + END + "\n")

	i=12
	while (i<pdulen):
		try :
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
			if os.path.isfile(INSTALLDIR+"/ROMs/" + name1 + ".zip"):
				print_line( YELLOW + "-!- " + B_GREEN + str(name1) + GRAY + " (" + GREEN + str(name2) + GRAY + ") -- " + str(name3) + "\n")
			else:
				print_line( YELLOW + "-!- " + B_GRAY + str(name1) + GRAY + " (" + str(name2) + ") -- " + str(name3) + "\n")
		except:
			if (DEBUG>0): print_line ( BLUE + "-!- Error parsing channel " + str(name1) + END + "\n")

	print_line ( YELLOW + "-!- EOF channel list." + END + "\n")

def pingcheck():
	global u, pinglist

	while 1:
		dgram, addr = u.recvfrom(64)
		if (DEBUG>0): print_line ( GRAY + "-!- UDP msg: " + dgram + " from " + str(addr) + END + "\n")
		if (dgram[0:9] == "GGPO PING"):
			val = dgram[10:]
			u.sendto("GGPO PONG " + val, addr)
			if (DEBUG>0): print_line( GRAY + "-!- UDP rpl: GGPO PONG " + val + " to " + str(addr) + END + "\n")
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
	sequence+=1
	print_line ( GREEN + "-!- accepted challenge request from " + B_GREEN + str(nick) + END + "\n")
	challengers.remove(nick)

def pdu_decline(nick):
	global sequence, challengers

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x0a" + pad(chr(nicklen)) + nick )
	sequence+=1
	print_line ( YELLOW + "-!- declined challenge request from " + B_YELLOW + str(nick) + END + "\n")
	challengers.remove(nick)

def pdu_cancel(nick):
	global sequence,challenged

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x1c" + pad(chr(nicklen)) + nick )
	sequence+=1
	print_line ( YELLOW + "-!- canceled challenge request to " + B_YELLOW + str(nick) + END + "\n")
	challenged.remove(nick)

def pdu_motd():
	global SPECIAL, sequence

	if (SPECIAL==""):
		pdulen = 4+4
		SPECIAL="MOTD"
		s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x02')
		sequence+=1

def pdu_users():
	global users_option, SPECIAL, sequence

	if (SPECIAL==""):
		users_option=line
		pdulen = 4+4
		SPECIAL="USERS"
		s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x04')
		sequence+=1

def mainloop():
	global sequence,SPECIAL,challengers,challenged,CHANNEL

	while 1:

		command = command_queue.get()

		print_line(PROMPT)

		if (command != "" and not command.startswith("/")):
			msglen = len(command)
			pdulen = 4 + 4 + 4 + msglen
			# [ 4-byte pdulen ] [ 4-byte sequence ] [ 4-byte command ] [ 4-byte msglen ] [ msglen-bytes msg ]
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x07" + pad(chr(msglen)) + command)
			sequence+=1

		# send a challenge request
		if (command != None and command.startswith("/challenge ")):
			nick = command[11:]
			nicklen = len(nick)
			channellen = len(CHANNEL)
			pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x08" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
			sequence+=1
			challenged.add(nick)
			print_line ( GREEN + "-!- challenge request sent to " + B_GREEN + str(nick) + END + "\n")
			print_line ( GREEN + "-!- type '/cancel " + B_GREEN + str(nick) + GREEN + "' to cancel it" + END + "\n")

		# accept a challenge request (initiated by peer)
		if (command != None and command.startswith("/accept ")):
			nick = command[8:]
			if nick in list(challengers):
				pdu_accept(nick)
			else:
				print_line ( YELLOW + "-!- " + B_YELLOW + str(nick) + YELLOW + " hasn't challenged you" + END + "\n")

		# if there's only one incoming challenge request, allow the user to type /accept without parameters (no need to specify nick)
		if (command == "/accept"):
			if (len(challengers)==1):
				for nick in list(challengers):
					pdu_accept(nick)
					break
			else:
				print_line ( YELLOW + "-!- " + "There's more than one incoming challenge request: you need to specify the nick." + END + "\n")

		# decline a challenge request (initiated by peer)
		if (command != None and command.startswith("/decline ")):
			nick = command[9:]
			if nick in list(challengers):
				pdu_decline(nick)
			else:
				print_line ( YELLOW + "-!- " + B_YELLOW + str(nick) + YELLOW + " hasn't challenged you" + END + "\n")

		# /decline without parameters declines all incoming challenge requests
		if (command == "/decline"):
			for nick in list(challengers):
				pdu_decline(nick)

		# cancel an ongoing challenge request (initiated by us)
		if (command != None and command.startswith("/cancel ")):
			nick = command[8:]
			if nick in list(challenged):
				pdu_cancel(nick)
			else:
				print_line ( YELLOW + "-!- you aren't challenging " + B_YELLOW + str(nick) + END + "\n")

		# /cancel without parameters: cancel all ongoing challenge requests
		if (command == "/cancel"):
			for nick in list(challenged):
				pdu_cancel(nick)

		# watch an ongoing match
		if (command != None and command.startswith("/watch ")):
			nick = command[7:]
			nicklen = len(nick)
			pdulen = 4 + 4 + 4 + nicklen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x10" + pad(chr(nicklen)) + nick )
			sequence+=1
			#print_line ( GREEN + "-!- watch challenge from " + B_GREEN + str(nick) + END + "\n")

		# choose channel
		if (command != None and command.startswith("/join ")):
			CHANNEL = command[6:]
			channellen = len(CHANNEL)
			pdulen = 4 + 4 + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x05" + pad(chr(channellen)) + CHANNEL )
			sequence+=1

		# set away status (can't be challenged)
		if (command == "/away"):
			pdulen = 4+4+4
			SPECIAL="AWAY"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x01')
			sequence+=1
			#print_line ( GREEN + "-!- you are away now" + END + "\n")

		# return back from away (can be challenged)
		if (command == "/back" or command == "/available"):
			pdulen = 4+4+4
			SPECIAL="BACK"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x00')
			sequence+=1
			#print_line ( GREEN + "-!- you are available now" + END + "\n")

		# view channel motd
		if (command == "/motd"):
			pdu_motd()

		# list channels
		if (command == "/list"):
			if (SPECIAL == ""):
				pdulen = 4+4
				SPECIAL="LIST"
				s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x03')
				sequence+=1

		# list users
		if (command != None and ( command.startswith("/users") or command.startswith("/whois ") or command=="/who" )):
			pdu_users()

def datathread():
	while 1:
		try:
			data = s.recv(4096)
		except:
			print_line ( BLUE + "-!- Connection lost. Reconnecting." + END + "\n")
			connect_sequence()
		if (data != None and len(data) >= 8):
			if (DEBUG>1): print_line ( BLUE + "HEX: " + repr(data) + END + "\n")
			parse(data)
		print_line(PROMPT)
		time.sleep(2)

def showverbose():
	text = YELLOW + "-!- " + GRAY + "current VERBOSE=" + B_GRAY + str(VERBOSE) + GRAY, 
	if (VERBOSE==0): text+= "only showing challenge requests/replies" + END,
	if (VERBOSE==1): text+= "showing challenges + chat" + END,
	elif (VERBOSE==2): text+= "showing challenges + chat + new matches" + END,
	elif (VERBOSE==3): text+= "showing challenges + chat + new matches + status changes" + END,
	text+="\n",
	print_line(' '.join(text))

def connect_sequence():
	global s, sequence

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('ggpo.net', 7000))

	# welcome packet
	sequence = 0x1
	s.send('\x00\x00\x00\x14' + pad(chr(sequence)) + '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x01')
	sequence+=1

	# authentication
	# NOTE: this must have sequence=2 as we use the server reply to identify 'incorrect password'
	pdulen = 4 + 4 + 4 + len(USERNAME) + 4 + len (PASSWORD) + 4
	s.send( pad(chr(pdulen)) + "\x00\x00\x00\x02" + "\x00\x00\x00\x01" + pad(chr(len(USERNAME))) + USERNAME + pad(chr(len(PASSWORD))) + PASSWORD + "\x00\x00\x17\x79")
	sequence+=1

	# choose channel
	# NOTE: this must have sequence=3 as we use the server reply to identify 'incorrect user'
	channellen = len(CHANNEL)
	pdulen = 4 + 4 + 4 + channellen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x05" + pad(chr(channellen)) + CHANNEL )
	sequence+=1

	# should we start away by default?
	if (STARTAWAY == 1):
		s.send( pad(chr(12)) + pad(chr(sequence)) + "\x00\x00\x00\x06" + "\x00\x00\x00\x01")
		sequence+=1


if __name__ == '__main__':

	DEBUG=0 # values: 0,1,2

	SPECIAL=""
	OLDDATA=""

	# initialize defaults for config
	USERNAME=""
	PASSWORD=""
	CHANNEL="lobby"
	INSTALLDIR=""
	VERBOSE=3
	STARTAWAY=0

	print_line ( YELLOW + "-!- " + BLUE + "GGPO PYTHON CLIENT " + B_BLUE + "VERSION " + VERSION + END + "\n")
	print_line ( YELLOW + "-!- " + BLUE + "(c) 2014 Pau Oliva Fora (" + B_BLUE + "pof" + BLUE + "). Licensed under GPLv2+." + END + "\n")

	# check for updates
	response = urllib2.urlopen('https://raw.github.com/poliva/ggpo/master/VERSION')
	version = response.read().strip()
	if (version != VERSION):
		print_line ( YELLOW + "-!- " + B_BLUE + "New version " + B_YELLOW + version + B_BLUE + " available at " + B_YELLOW + "http://poliva.github.io/ggpo/" + END + "\n")

	HOMEDIR = os.path.expanduser("~")
	CONFIGDIR= HOMEDIR + "/.config/ggpo"
	CONFIGFILE = CONFIGDIR + "/ggpo.config"

	if not os.path.exists(CONFIGDIR):
		os.makedirs(CONFIGDIR)

	try:
		configfile = open(CONFIGFILE, "r")
	except IOError:
		# file does not exist, create it for the first time:
		try:
			configfile = open(CONFIGFILE, "w")
		except IOError:
			print_line ( RED + "-!- ERROR: cannot write to config file at " + CONFIGFILE + END + "\n")
			os._exit(1)

		print_line ( "\n" + BLUE + "-!- It looks like you're running ggpo for the first time, let's configure it!" + END + "\n")
		print_line ( BLUE + "-!- This quick setup will create a config file at:\n\t" + GREEN + CONFIGFILE + END + "\n")

		# try to guess install directory:

		# directory of the script being run
		dirtest1 = os.path.dirname(os.path.abspath(__file__))
		# current working directory
		dirtest2 = os.getcwd()

		if (os.path.isfile(dirtest1+"/ggpofba.exe")):
			INSTALLDIR=dirtest1
			print_line( "\n" + BLUE + "-!- Found GGPO install dir at: " + GREEN + INSTALLDIR + END + "\n")
		elif (os.path.isfile(dirtest2+"/ggpofba.exe")):
			INSTALLDIR=dirtest2
			print_line( "\n" + BLUE + "-!- Found GGPO install dir at: " + GREEN + INSTALLDIR + END + "\n")
		else:
			print_line( "\n" + BLUE + "-!- Please specify the full path where you have unziped the official GGPO client" + END + "\n")
			try:
				INSTALLDIR = raw_input("\r" + BLUE + "GGPO INSTALLDIR:" + END + " ")
			except KeyboardInterrupt:
				print_line( "\n" + RED + "-!- ^C interrupted." + END + "\n")
				configfile.close()
				os.unlink(CONFIGFILE)
				os._exit(1)

		if not os.path.isfile(INSTALLDIR+"/ggpofba.exe"):
			print_line ( YELLOW + "-!- WARNING: cannot find ggpofba.exe in " + INSTALLDIR + END + "\n")

		print_line( "\n" + BLUE + "-!- Please specify your GGPO credentials" + END + "\n")
		try:
			USERNAME = raw_input("\r" + BLUE + "GGPO USERNAME:" + END + " ")
			PASSWORD = raw_input("\r" + BLUE + "GGPO PASSWORD:" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + RED + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

		print_line( "\n" + BLUE + "-!- Please specify your GGPO game room, if unsure type 'lobby'" + END + "\n")
		try:
			CHANNEL = raw_input("\r" + BLUE + "GGPO CHANNEL:" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + RED + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

		if not os.path.isfile(INSTALLDIR+"/ROMs/" + CHANNEL + ".zip") and CHANNEL!="lobby":
			print_line ( YELLOW + "-!- WARNING: cannot find " + CHANNEL + ".zip in " + INSTALLDIR + "/ROMs/" + END + "\n")

		configfile.write("#GGPO configuration file\n")
		configfile.write("USERNAME=" + USERNAME + "\n")
		configfile.write("PASSWORD=" + PASSWORD + "\n")
		configfile.write("CHANNEL=" + CHANNEL + "\n")
		configfile.write("INSTALLDIR=" + INSTALLDIR + "\n")
		configfile.write("VERBOSE=3\n")
		configfile.write("STARTAWAY=0\n")
		configfile.close()

		print_line( "\n" + BLUE + "-!- Thank you, configuration is completed!" + END + "\n")
		try:
			raw_input("\r" + BLUE + "-!- Press ENTER to connect for the fist time" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + RED + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

	try:
		configfile = open(CONFIGFILE, "r")
	except IOError:
		print_line ( RED + "-!- ERROR: cannot read config file at " + CONFIGFILE + END + "\n")
		os._exit(1)

	# parse configuration file
	for line in iter(configfile):
		#print line
		if (line.startswith("USERNAME=")): USERNAME=line[9:].strip()
		if (line.startswith("PASSWORD=")): PASSWORD=line[9:].strip()
		if (line.startswith("CHANNEL=")): CHANNEL=line[8:].strip()
		if (line.startswith("INSTALLDIR=")): INSTALLDIR=line[11:].strip()
		if (line.startswith("VERBOSE=")): VERBOSE=int(line[8:].strip())
		if (line.startswith("STARTAWAY=")): STARTAWAY=int(line[10:].strip())
	configfile.close()

	print_line ( YELLOW + "-!- " + BLUE + "If you are lost type '/help' and press enter." + END + "\n")

	FBA = INSTALLDIR + "/ggpofba.sh"
	MP3 = INSTALLDIR + "/assets/challenger-comes.mp3"

	u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
	try:
		u.bind(('0.0.0.0', 6009))
	except socket.error:
		print_line ( YELLOW + "-!- WARNING: cannot bind to port udp/6009" + END + "\n")

	t = Thread(target=pingcheck)
	t.daemon = True
	t.start()

	s=''
	connect_sequence()

	command=""
	challengers=set()
	challenged=set()
	users_option=""
	pinglist=[]
	userlist=[]

	command_queue = Queue()

	t2 = Thread(target=datathread)
	t2.daemon = False
	t2.start()

	t3 = Thread(target=mainloop)
	t3.daemon = False
	t3.start()

	while 1:
		command = raw_input(PROMPT)
		command = command.strip(' \t\n\r')

		if (command == "/help"):
			print_line ( YELLOW + "-!- " + BLUE + "available commands:" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/challenge [<nick>]\tsend a challenge request to <nick>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/cancel    [<nick>]\tcancel an ongoing challenge request to <nick>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/accept    [<nick>]\taccept a challenge request initiated by <nick>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/decline   [<nick>]\tdecline a challenge request initiated by <nick>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/watch      <nick>\twatch the game that <nick> is currently playing" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/whois      <nick>\tdisplay information about the user <nick>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/whowas     <nick>\tinfo about <nick> that is no longer connected" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/join    <channel>\tjoin the chat/game room <channel>" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/list \t\tlist all available channels or chat/game rooms" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/users [<modifier>]\tlist all users in the current channel" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "         modifier: 'available', 'away' or 'playing'" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/motd \t\tview the channel welcome text" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/away \t\tset away status (you can't be challenged)" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/back \t\tset available status (you can be challenged)" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/clear \t\tclear the screen" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/verbose [<flag>]\tchange verbosity level" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "           flag:'0' challenges, '1' chat, '2' match, '3' status" + END + "\n")
			print_line ( YELLOW + "-!- " + BLUE + "/quit \t\tdisconnect from ggpo server" + END + "\n")

		elif (command.startswith("/whowas ")):
			nick = command[8:]
			found = print_user_long(nick,"whowas")
			if (found==1):
				print_line ( YELLOW + "-!- " + GRAY + "End of WHOWAS" + END + "\n")
			else:
				print_line ( YELLOW + "-!- There was no such nick " + B_YELLOW + nick + END + "\n")

		# hidden command, not present in /help
		elif (command.startswith("/debug ")):
			debug = command[7:]
			if (debug == "0"): DEBUG=0
			elif (debug == "1"): DEBUG=1
			elif (debug == "2"): DEBUG=2
			else: print_line ( YELLOW + "-!- possible values are /debug [<0|1|2>]" + END + "\n")
		elif (command == "/debug"):
			print_line ( YELLOW + "-!- " + GRAY + "DEBUG: " + str(DEBUG) + END + "\n")

		elif (command.startswith("/verbose ")):
			verbose = command[9:]
			if (verbose == "0"): VERBOSE=0
			elif (verbose == "1"): VERBOSE=1
			elif (verbose == "2"): VERBOSE=2
			elif (verbose == "3"): VERBOSE=3
			else: print_line ( YELLOW + "-!- possible values are /verbose [<0|1|2|3>]" + END + "\n")
			showverbose()

		elif (command == "/verbose"):
			showverbose()

		elif (command == "/challenge"):
			text= YELLOW + "-!- " + GRAY + "challenging:",
			for nick in challenged:
				text+= "["+ B_GREEN + nick + GRAY + "]",
			text+=END+"\n",
			print_line(' '.join(text))

		elif (command == "/clear"):
			call(['clear'])

		elif (command == "/quit"):
			s.close()
			u.close()
			#call(['reset'])
			print_line ( YELLOW + "-!- " + BLUE + "have a nice day :)" + END + "\n")
			os._exit(0)
		else:
			command_queue.put(command)
