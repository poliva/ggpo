#!/usr/bin/python
# -*- coding: utf-8 -*-
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
import rlcompleter
import termios
import fcntl
import urllib2
import re
from Queue import Queue
from subprocess import call, Popen, PIPE
from threading import Thread
from threading import Event
from random import randint
from operator import itemgetter

VERSION = "1.2"

def reset_autocomplete():
	global AUTOCOMPLETE
	AUTOCOMPLETE = ['/challenge', '/cancel', '/accept', '/decline', '/watch', '/whois', '/whowas', '/join', '/list', '/users', '/motd', '/away', '/back', '/clear', '/verbose', '/quit', '/who', '/names', '/debug', '/ping', '/autochallenge', '/challengewa', '/notify', '/play', '/ignore', '/xchallenge', '/help']

def complete(text, state):
    for cmd in AUTOCOMPLETE:
        if cmd.startswith(text):
            if not state:
                return cmd
            else:
                state -= 1

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
	if (LOGFILE != "" or TIMESTAMP==1):
		date = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M')
	if (LOGFILE != "" and text!=PROMPT):
		try:
			logfile.write("[" + date + "] " + text)
		except:
			pass

	if (TIMESTAMP == 1):
		if (text!=PROMPT): print "["+date+"]", text,
		else: print text,
	else:
		print text,
	if (text == PROMPT and "\n" in linebuffer):
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

def send_notification(msg):
	args = ['notify-send', '--icon=' + INSTALLDIR + '/assets/icon-128.png', msg ]
	try:
		FNULL = open(os.devnull, 'w')
		call(args, stdout=FNULL, stderr=FNULL)
		FNULL.close()
	except OSError:
		pass

def disable_autochallenge():
	global autochallenge
	if (autochallenge > 0):
		autochallenge=0
		print_line ( COLOR2 + "-!- setting autochallenge to " + B_COLOR2 + "off" + END + "\n")
		command_queue.put("/cancel")

def parse(cmd):
	global challengers,challenged,sequence,playing_against,autochallenge

	pdulen = int(cmd[0:4].encode('hex'), 16)
	action = cmd[4:8]

	# chat
	if (action == "\xff\xff\xff\xfe"):
		if (VERBOSE>0):
			nicklen = int(cmd[8:12].encode('hex'),16)
			nick = cmd[12:12+nicklen]
			msglen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
			msg = cmd[12+nicklen+4:pdulen+4].replace('\r','\n')
			if nick not in IGNORE:
				if (USERNAME+" " in msg or " "+USERNAME in msg or msg==USERNAME):
					send_notification(msg)
					msg = msg.replace(USERNAME, B_COLOR3 + USERNAME + END)

				print_line ( COLOR6 + "<" + str(nick) + "> " + END + str(msg) + "\n")

	# state changes (away/available/playing)
	elif (action == "\xff\xff\xff\xfd"):

		unk1 = cmd[8:12]
		unk2 = cmd[12:16]

		nicklen = int(cmd[16:20].encode('hex'),16)
		nick = cmd[20:20+nicklen]


		if (unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x00"):
			if (VERBOSE>2): print_line ( COLOR0 + "-!- " + B_COLOR0 + str(nick) + COLOR0 +" has quit" + END +"\n")
			if nick in AUTOCOMPLETE: AUTOCOMPLETE.remove(nick)
			for user in available_users:
				if (nick==user[0]): available_users.remove(user)
			for user in away_users:
				if (nick==user[0]): away_users.remove(user)
			for user in playing_users:
				if (nick==user[0]): playing_users.remove(user)

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

					iplen = int(cmd[28+nicklen+nick2len:32+nicklen+nick2len].encode('hex'),16)
					ip = cmd[32+nicklen+nick2len:32+nicklen+nick2len+iplen]

					unk6 = cmd[32+nicklen+iplen+nick2len:32+nicklen+iplen+4+nick2len]
					unk7 = cmd[36+nicklen+iplen+nick2len:36+nicklen+iplen+4+nick2len]

					citylen = int(cmd[40+nicklen+iplen+nick2len:44+nicklen+iplen+nick2len].encode('hex'),16)
					city = cmd[44+nicklen+iplen+nick2len:44+nicklen+iplen+citylen+nick2len]

					cclen = int(cmd[44+nicklen+iplen+citylen+nick2len:48+nicklen+iplen+citylen+nick2len].encode('hex'),16)
					cc = cmd[48+nicklen+iplen+citylen+nick2len:48+nicklen+iplen+citylen+cclen+nick2len]

					countrylen = int(cmd[48+nicklen+iplen+citylen+cclen+nick2len:48+nicklen+iplen+citylen+cclen+4+nick2len].encode('hex'),16)
					country = cmd[52+nicklen+iplen+citylen+cclen+nick2len:52+nicklen+iplen+citylen+cclen+countrylen+nick2len]

					print_line ( COLOR5 + "-!- new match " + B_COLOR5 + str(nick) + COLOR5 + " vs " + B_COLOR5 + str(nick2) + END +"\n" )

					# remove from challenged set when nick2 accepts our challenge
					if (nick==USERNAME and nick2 in list(challenged)): challenged.remove(nick2)

					# port is hardcoded because i don't know how to retrieve it without requesting the full user list to the server
					add_to_userlist(nick,ip,city,cc,country,6009,state,nick2)

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

				# port is hardcoded because i don't know how to retrieve it without requesting the full user list to the server
				check_ping(nick,ip,6009)
				time.sleep(1) # sleep 1sec to collect ping data
				add_to_userlist(nick,ip,city,cc,country,6009,state,'')

				if (VERBOSE>2):

					text = COLOR0 + "-!- " + B_COLOR0 + str(nick) + COLOR0 + "@" + str(ip), 
					if (city != "" and cc != ""): text+= "(" + city + ", " + cc + ")",
					elif (city == "" and cc != ""): text+= "(" + cc + ")",
					if nick not in AUTOCOMPLETE and nick != USERNAME:
						text+="has joined and",
						AUTOCOMPLETE.append(nick)
					if (state == 0):
						text+= "is available",
						ping = get_ping_msec(nick)
						if (ping != 0): text+="[" + str(int(ping)) + " ms]",
					if (state == 1): text+= "is away",
					text+=END+"\n",
					print_line(' '.join(text))

				# NOTIFY
				if (nick in NOTIFY and state==0):
					print_line ( COLOR2 + "-!- NOTIFY: " + B_COLOR2 + nick + COLOR2 + " IS NOW AVAILABLE" + END + "\n")
					send_notification("NOTIFY: " + nick + " is now available")

				# autochallenge
				if (autochallenge > 0 and nick!=USERNAME and nick!=playing_against and state==0):
					user = get_user_info(nick)
					ping = user[8]
					if (ping>0 and ping<autochallenge):
						command_queue.put("/challenge " + nick)

				# challengewa
				for p2 in list(challengewa):
					if (nick==p2 and state==0):
						command_queue.put("/challenge " + nick)
						challengewa.remove(nick)

				# auto-kill ggpofba when p2 quits the game
				if (nick == USERNAME): playing_against=''
				if (nick == playing_against):
					args = ['pkill', '-f', 'ggpofba.exe']
					try:
						FNULL = open(os.devnull, 'w')
						call(args, stdout=FNULL, stderr=FNULL)
						FNULL.close()
					except OSError:
						pass

		else:
			if (DEBUG>0): print_line ( COLOR4 + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END +"\n")

	# challenge request declined by peer
	elif (action == "\xff\xff\xff\xfb"):
		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]
		if nick in list(challenged): challenged.remove(nick)
		print_line ( COLOR1 + "-!- " + B_COLOR1 + str(nick) + COLOR1 + " declined the challenge request" + END +"\n")


	# challenge
	elif (action == "\xff\xff\xff\xfc"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		if nick not in IGNORE:

			channellen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
			channel = cmd[16+nicklen:16+nicklen+channellen]

			user = get_user_info(nick)
			ping = user[8]
			cc = user[3]
			text = COLOR1 + "-!- INCOMING CHALLENGE REQUEST FROM " + B_COLOR1 + str(nick) + COLOR1,
			if (cc!=""): text+="(" + cc + ")",
			if (ping != 0): text+="[" + str(int(ping)) + " ms]",
			text+="@ " + channel + END +"\n",
			print_line(' '.join(text))

			if (len(challengers)>0):
				print_line ( COLOR1 + "-!- TYPE '/accept " + B_COLOR1 + str(nick) + COLOR1 + "' to accept it, or '/decline " + B_COLOR1 + str(nick) + COLOR1 + "' to wimp out." + END +"\n")
			else:
				print_line ( COLOR1 + "-!- TYPE '/accept' to accept it, or '/decline' to wimp out." + END +"\n")

			challengers.add(nick)

			args = ['afplay', MP3]
			try:
				FNULL = open(os.devnull, 'w')
				call(args, stdout=FNULL, stderr=FNULL)
				FNULL.close()
			except OSError:
				args = ['ffplay', '-nodisp', '-autoexit', MP3]
				try:
					FNULL = open(os.devnull, 'w')
					call(args, stdout=FNULL, stderr=FNULL)
					FNULL.close()
				except OSError:
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
		print_line ( COLOR3 + "-!- CHALLENGE REQUEST CANCELED BY " + B_COLOR3 + str(nick) + END + "\n")


	# joining a channel
	elif (action == "\xff\xff\xff\xff"):
		print_line ( COLOR0 + "-!- connection established" + END + "\n")
		command_queue.put("/motd")
		command_queue.put("/names")
		notifyjoin=1

	# password incorrect (reply to request with sequence=2)
	elif (action == "\x00\x00\x00\x02"):
		result = cmd[8:12]
		if (result == "\x00\x00\x00\x06"):
			s.close()
			u.close()
			call(['reset'])
			print_line ( COLOR1 + "-!- password incorrect" + END + "\n")
			print_line ( COLOR1 + "-!- check config file at " + CONFIGFILE + END + "\n")
			if (LOGFILE!=""): logfile.close()
			os._exit(0)

	# reply to request with sequence=3
	elif (action == "\x00\x00\x00\x03"):
		result = cmd[8:12]
		# user incorrect
		if (result == "\x00\x00\x00\x04"):
			s.close()
			u.close()
			call(['reset'])
			print_line ( COLOR1 + "-!- user incorrect" + END + "\n")
			print_line ( COLOR1 + "-!- check config file at " + CONFIGFILE + END + "\n")
			if (LOGFILE!=""): logfile.close()
			os._exit(0)

	# watch
	elif (action == "\xff\xff\xff\xfa"):

		nick1len = int(cmd[8:12].encode('hex'),16)
		nick1 = cmd[12:12+nick1len]
		nick2len = int(cmd[12+nick1len:16+nick1len].encode('hex'),16)
		nick2 = cmd[16+nick1len:16+nick1len+nick2len]

		# auto-cancel all outgoing challenge requests when a match becomes active
		if (nick1 == USERNAME):
			command_queue.put("/cancel")
			playing_against=nick2
			disable_autochallenge()
		else:
			print_line ( COLOR2 + "-!- watch " + B_COLOR2 + str(nick1) + COLOR2 + " vs " + B_COLOR2 + str(nick2) + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ggpofba.sh"):
			print_line ( COLOR3 + "-!- WARNING: cannot find ggpofba.sh in " + INSTALLDIR + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ggpofba.exe"):
			print_line ( COLOR3 + "-!- WARNING: cannot find ggpofba.exe in " + INSTALLDIR + END + "\n")

		if not os.path.isfile(INSTALLDIR+"/ROMs/" + CHANNEL + ".zip"):
			print_line ( COLOR3 + "-!- WARNING: cannot find game ROM at " + INSTALLDIR + "/ROMs/" + CHANNEL + ".zip" + END + "\n")

		quark = cmd[20+nick1len+nick2len:pdulen+4]
		if quark.startswith('quark:served'):
			quark = quark + "," + str(SMOOTHING)
		args = [FBA, quark]
		try:
			FNULL = open(os.devnull, 'w')
			call(args, stdout=FNULL, stderr=FNULL)
			FNULL.close()
		except OSError:
			print_line ( COLOR1 + "-!- ERROR: can't execute " + FBA + END + "\n")

	# unknown action
	else:
		if (len(special)==0):
			if (DEBUG>0): print_line ( COLOR4 + "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4]) + END + "\n")
			#if (cmd[8:pdulen+4]=="\x00\x00\x00\x00" and int(action.encode('hex'),16)>4): print "ggpo> ",
		else:
			parsespecial(cmd)

	#print ("PDULEN: " + str(pdulen) + " ACTION: " + str(action))
	#print ("PDULEN: " + str(pdulen) + " CMDLEN: " + str(len(cmd)))
	if ( len(cmd) > pdulen+4 and len(cmd[pdulen+4:]) >=8 ):
		parse(cmd[pdulen+4:])
		

def parsespecial(cmd):

	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
	except:
		pdulen = 0

	SPECIAL=special.pop()

	if (SPECIAL=="MOTD"):
		parsemotd(cmd)

	elif (SPECIAL=="LIST"):
		parselist(cmd)

	elif (SPECIAL=="USERS"):
		SPECIAL=""
		parseusers(cmd)

def parsemotd(cmd):
	try:
		channellen = int(cmd[12:12+4].encode('hex'),16)
		channel = cmd[16:16+channellen]

		topiclen = int(cmd[16+channellen:20+channellen].encode('hex'),16)
		topic = cmd[20+channellen:20+channellen+topiclen]

		msglen = int(cmd[20+channellen+topiclen:24+channellen+topiclen].encode('hex'),16)
		msg = cmd[24+channellen+topiclen:24+channellen+topiclen+msglen]

		print_line ( B_COLOR2 + str(channel) + COLOR2 + " || " + B_COLOR2 + str(topic) + END + "\n")
		print_line ("-------------------------------------------------------------------------------\n")
		print_line ( COLOR2 + str(msg) + END)
		print_line ("-------------------------------------------------------------------------------\n")
	except ValueError:
		pass

def check_latency(ip):
	global CHECKLATENCY
	# we use this as a fallback mehtod to display ping value for users that do not have the UDP port open
	p1 = Popen(['traceroute', '-n', '-q', '1', '-w', '0.3', '-N', '1', '-m', '20', ip, '2>&1'],stdout=PIPE)
	p2 = Popen(['grep', ' ms$'], stdin=p1.stdout, stdout=PIPE)
	p3 = Popen(['rev'], stdin=p2.stdout, stdout=PIPE)
	p4 = Popen(['cut', '-f2', '-d', ' '], stdin=p3.stdout, stdout=PIPE)
	p5 = Popen(['rev'], stdin=p4.stdout, stdout=PIPE)
	p6 = Popen(['cut', '-f1', '-d', '.'], stdin=p5.stdout, stdout=PIPE)
	p7 = Popen(['sort', '-nr'], stdin=p6.stdout, stdout=PIPE)
	p8 = Popen(['head', '-n1'], stdin=p7.stdout, stdout=PIPE)
	latency = p8.communicate()[0].strip()
	try:
		ping = int(latency)
	except ValueError:
		ping = 0
		print_line ( COLOR3 + "-!- WARNING: Latency check not supported in this system. Disabling it." + END + "\n")
		CHECKLATENCY=0
	return ping

def check_ping(nick,ip,port):
	global pinglist

	if (ip==''): return
	if (port==''): port=6009
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

def get_ping_msec(nick):
	ping = 0
	for i in range( len( pinglist ) ):
		if (pinglist[i][1]==nick):
			ping = pinglist[i][5]

			if (ping == 0 and CHECKLATENCY==1):
				user = get_user_info(nick)
				ip = user[1]
				if (ip != ""):
					ping = check_latency(ip)
					#print_line ( COLOR3 + "-!- latency for user " + str(nick) + ": " + str(ping) + END + "\n")
					pinglist[i][5] = ping

			break
	return ping

def get_user_info(nick):
	user = ['','','','','','','','',0]
	for i in range( len( userlist ) ):
		if (userlist[i][0]==nick):
			user = userlist[i]
			break
	return user

def sort_lists():
	global userlist, available_users, away_users, playing_users

	# create 3 lists
	available_users=[]
	away_users=[]
	playing_users=[]

	for user in userlist:
		nick=user[0]
		ip=user[1]
		user[8]=get_ping_msec(nick)
		# put the users on each list
		status=user[6]
		if (status == 0): available_users.append(user)
		elif (status == 1): away_users.append(user)
		elif (status == 2): playing_users.append(user)
		# trick to have users with no ping sorted at the end
		if (user[8]==0): user[8]=9999

	# sort userlist by ping value
	userlist = sorted(userlist, key=itemgetter(8), reverse=False)
	available_users = sorted(available_users, key=itemgetter(8), reverse=False)
	away_users = sorted(away_users, key=itemgetter(8), reverse=False)
	playing_users = sorted(playing_users, key=itemgetter(8), reverse=False)

	# reverse the ping-sorting trick
	for user in userlist:
		if (user[8]==9999): user[8]=0
	for user in available_users:
		if (user[8]==9999): user[8]=0
	for user in away_users:
		if (user[8]==9999): user[8]=0
	for user in playing_users:
		if (user[8]==9999): user[8]=0

def add_to_userlist(nick,ip,city,cc,country,port,status,p2nick):

	found=False
	for i in range(len(userlist)):
		if (userlist[i][0]==nick):
			found=True
			break

	ping = get_ping_msec(nick)
	if (found==False):
		user = [nick,ip,city,cc,country,port,status,p2nick,ping]
		userlist.append(user)
	else:
		# update info
		userlist[i][1]=ip
		userlist[i][2]=city
		userlist[i][3]=cc
		userlist[i][4]=country
		# skip port number (could be hardcoded, so better leave the one we have)
		userlist[i][6]=status
		userlist[i][7]=p2nick
		userlist[i][8]=ping
	sort_lists()

def parseusers(cmd):
	global userlist,notifyjoin

	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
	except:
		pdulen = 0

	userlist=[]

	i=16
	while (i<pdulen):

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
			# add user to autocomplete list
			if nick not in AUTOCOMPLETE and nick != USERNAME: AUTOCOMPLETE.append(nick)
		except:
			if (DEBUG>0): print_line ( COLOR4 + "error parsing user " + str(nick) + END + "\n")
			else: pass

	# sleep 1sec to collect ping data
	time.sleep(1)

	sort_lists()

	if (notifyjoin==1):
		notifyjoin=0
		found=False
		for a_user in available_users:
			for nick in NOTIFY:
				if (a_user[0]==nick):
					print_line ( COLOR2 + "-!- NOTIFY: " + B_COLOR2 + nick + COLOR2 + " IS NOW AVAILABLE" + END + "\n")
					send_notification("NOTIFY: " + nick + " is now available")

	if (users_option.startswith("/whois ")):
		query=users_option[7:]

		found = print_user_long(query,"whois")
		if (found == 1):
			print_line ( COLOR3 + "-!- " + COLOR0 + "end of WHOIS" + END + "\n")
		else:
			print_line ( COLOR3 + "-!- there is no such nick " + B_COLOR3 + query + END + "\n")

	elif (users_option.startswith("/users ")):
		subcmd=users_option[7:]

		print_line ( COLOR3 + "-!- user list:" + END + "\n")
		if (subcmd == "available"):
			for user in available_users: print_user(user)
		elif (subcmd=="away"):
			for user in away_users: print_user(user)
		elif (subcmd=="playing"):
			for user in playing_users: print_user(user)
		else:
			print_line ( COLOR3 + "-!- possible modifiers are: available, away, playing" + END + "\n")

		print_line ( COLOR3 + "-!- EOF user list." + END + "\n")

	elif (users_option=="/who" or users_option=="/users"):
		print_line ( COLOR3 + "-!- user list:" + END + "\n")
		for user in available_users: print_user(user)
		for user in playing_users: print_user(user)
		for user in away_users: print_user(user)
		print_line ( COLOR3 + "-!- EOF user list." + END + "\n")

	elif (users_option=="/names" or users_option.startswith("/names ")):
		subcmd=users_option[7:]
		i=0
		text="\r" + COLOR0,
		if (subcmd == "available" or subcmd==""):
			for user in available_users:
				i+=1
				nick=user[0]
				if (len(nick) > 13): nick=''.join(nick[0:12]+"…")
				text+= COLOR0 + "["+ B_COLOR2 + '{:13s}'.format(nick) + COLOR0 + "]",
				if (i%5==0): text+=END+"\n",
		if (subcmd == "playing" or subcmd==""):
			for user in playing_users:
				i+=1
				nick=user[0]
				if (len(nick) > 13): nick=''.join(nick[0:12]+"…")
				text+= COLOR0 + "["+ B_COLOR5 + '{:13s}'.format(nick) + COLOR0 + "]",
				if (i%5==0): text+=END+"\n",
		if (subcmd == "away" or subcmd==""):
			for user in away_users:
				i+=1
				nick=user[0]
				if (len(nick) > 13): nick=''.join(nick[0:12]+"…")
				text+= COLOR0 + "["+ B_COLOR4 + '{:13s}'.format(nick) + COLOR0 + "]",
				if (i%5==0): text+=END+"\n",
		if (subcmd != "away" and subcmd != "available" and subcmd != "playing" and subcmd != ""):
			text+= COLOR3 + "-!- possible modifiers are: available, away, playing",
		if (i%5!=0): text+=END+"\n",

		print_line(''.join(text))

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

	print_line ( COLOR3 + "-!- " + B_COLOR0 + str(nick) + COLOR0 + "@" + str(ip) + ":" + str(port) + END + "\n")
	if (command == "whois"): print_line ( COLOR3 + "-!- " + COLOR0 + "  channel  : " + CHANNEL + END + "\n")
	print_line ( COLOR3 + "-!- " + COLOR0 + "  hostname : " + hostname[0] + END + "\n")
	if (lastseen != ""): print_line ( COLOR3 + "-!- " + COLOR0 + "  lastseen : " + datetime.datetime.fromtimestamp(int(lastseen)).strftime('%Y-%m-%d %H:%M:%S') + END + "\n")
	text = COLOR3 + "-!- " + COLOR0 + "  location :",
	if (city != "" and cc != ""): text+= city + ", " + cc + ", " + country,
	elif (city == "" and cc != ""): text+= cc + ", " + country,
	else: text+= "unknown",
	text+=END+"\n",
	print_line (' '.join(text))
	text = COLOR3 + "-!- " + COLOR0 + "  status   :",
	if (status == 0): text+= "available",
	if (status == 1): text+= "away",
	if (status == 2): text+= "playing against " + B_COLOR0 + p2nick,
	text+=END+"\n",
	print_line (' '.join(text))
	if (ping != 0): print_line ( COLOR3 + "-!- " + COLOR0 + "  ping     : " + str(int(ping)) + " ms" + END + "\n")
	if nick in challenged:
		print_line ( COLOR3 + "-!- " + COLOR0 + " you have challenged " + B_COLOR0 + str(nick) + END + "\n")
	if nick in challengers:
		print_line ( COLOR3 + "-!- " + B_COLOR0 + str(nick) + COLOR0 + " has challenged you" + END + "\n")
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

	if (ping==0): ping = get_ping_msec(nick)
	text = COLOR3 + "-!-" + B_COLOR0,
	if nick in NOTIFY:
		if (status==0): text= COLOR3 + "-!-" + B_COLOR2,
		if (status==1): text= COLOR3 + "-!-" + B_COLOR4,
		if (status==2): text= COLOR3 + "-!-" + B_COLOR5,
	text+= str(nick) + COLOR0 + "@" + str(ip),
	if (city != "" and cc != ""): text+= "(" + city + ", " + cc + ")",
	elif (city == "" and cc != ""): text+= "(" + cc + ")",
	if (status == 0): text+= "is available",
	if (status == 1): text+= "is away",
	if (status == 2): text+= "is playing against " + B_COLOR0 + p2nick,
	if (ping != 0): text+= COLOR0 + "[" + str(int(ping)) + " ms]",
	if nick in challenged:
		text+= COLOR2 + "*challenged",
	if nick in challengers:
		text+= COLOR1 + "*challenging",
	text+=END+"\n",
	print_line(' '.join(text))

def parselist(cmd):
	try:
		pdulen = int(cmd[0:4].encode('hex'), 16)
	except:
		pdulen = 0

	print_line ( COLOR3 + "-!- channel list:" + END + "\n")

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
				print_line( COLOR3 + "-!- " + B_COLOR2 + str(name1) + COLOR0 + " (" + COLOR2 + str(name2) + COLOR0 + ") -- " + str(name3) + "\n")
			else:
				print_line( COLOR3 + "-!- " + B_COLOR0 + str(name1) + COLOR0 + " (" + str(name2) + ") -- " + str(name3) + "\n")
		except:
			if (DEBUG>0): print_line ( COLOR4 + "-!- error parsing channel " + str(name1) + END + "\n")
			else: pass

	print_line ( COLOR3 + "-!- EOF channel list." + END + "\n")

def pingcheck():
	global pinglist

	while 1:
		dgram, addr = u.recvfrom(64)
		if (DEBUG>0): print_line ( COLOR0 + "-!- UDP msg: " + dgram + " from " + str(addr) + END + "\n")
		if (dgram[0:9] == "GGPO PING"):
			val = dgram[10:]
			u.sendto("GGPO PONG " + val, addr)
			if (DEBUG>0): print_line( COLOR0 + "-!- UDP rpl: GGPO PONG " + val + " to " + str(addr) + END + "\n")
		if (dgram[0:9] == "GGPO PONG"):
			mytime = time.time()
			val = dgram[10:]
			for i in range( len( pinglist ) ):
				if (pinglist[i][4]==val and pinglist[i][2]==addr[0]):
					msec = (mytime-pinglist[i][0])*1000
					pinglist[i][5]=msec
					break

def pdu_accept(nick):
	global sequence,challengers,playing_against

	nicklen = len(nick)
	channellen = len(CHANNEL)
	playing_against=nick
	disable_autochallenge()
	pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x09" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
	sequence+=1
	print_line ( COLOR2 + "-!- accepted challenge request from " + B_COLOR2 + str(nick) + END + "\n")
	challengers.remove(nick)

def pdu_decline(nick):
	global sequence, challengers

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x0a" + pad(chr(nicklen)) + nick )
	sequence+=1
	print_line ( COLOR3 + "-!- declined challenge request from " + B_COLOR3 + str(nick) + END + "\n")
	challengers.remove(nick)

def pdu_cancel(nick):
	global sequence,challenged

	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x1c" + pad(chr(nicklen)) + nick )
	sequence+=1
	print_line ( COLOR3 + "-!- canceled challenge request to " + B_COLOR3 + str(nick) + END + "\n")
	challenged.remove(nick)

def pdu_motd():
	global sequence
	pdulen = 4+4
	special.append("MOTD")
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x02')
	sequence+=1

def pdu_users(command):
	global users_option, sequence
	users_option=command
	pdulen = 4+4
	special.append("USERS")
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x04')
	sequence+=1

def pdu_chat(message):
	global sequence
	msglen = len(message)
	pdulen = 4 + 4 + 4 + msglen
	# [ 4-byte pdulen ] [ 4-byte sequence ] [ 4-byte command ] [ 4-byte msglen ] [ msglen-bytes msg ]
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x07" + pad(chr(msglen)) + message)
	sequence+=1

def pdu_challenge(nick):
	global sequence,challenged
	user = get_user_info(nick)
	state = user[6]
	if (state == 0):
		nicklen = len(nick)
		channellen = len(CHANNEL)
		pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
		s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x08" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
		sequence+=1
		ping = user[8]
		cc = user[3]
		text = COLOR2 + "-!-",
		if (autochallenge>0): text+="autochallenge",
		else: text+="challenge",
		text +="request sent to " + B_COLOR2 + str(nick) + COLOR2,
		if (cc!=""): text+="(" + cc + ")",
		if (ping != 0): text+="[" + str(int(ping)) + " ms]",
		text+=END +"\n",
		print_line(' '.join(text))
		if (len(challenged)>0):
			text = COLOR2 + "-!- type '/cancel " + B_COLOR2 + str(nick) + COLOR2 + "' to cancel it",
		else:
			text = COLOR2 + "-!- type '/cancel' to cancel it",
		if (autochallenge>0):
			text+="or '/autochallenge off' to disable autochallenge",
		text+=END +"\n",
		print_line(' '.join(text))
		challenged.add(nick)
	elif (state==1):
		print_line ( COLOR3 + "-!- " + B_COLOR3 + str(nick) + COLOR3 + " is away. Can't challenge." + END + "\n")
	elif (state==2):
		p2nick = user[7]
		print_line ( COLOR3 + "-!- " + B_COLOR3 + str(nick) + COLOR3 + " is playing against " + B_COLOR3 + str(p2nick) + COLOR3 +". Can't challenge." + END + "\n")
	elif (state==''):
		print_line ( COLOR3 + "-!- unknown user " + B_COLOR3 + str(nick) + END + "\n")

def pdu_watch(nick):
	global sequence
	nicklen = len(nick)
	pdulen = 4 + 4 + 4 + nicklen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x10" + pad(chr(nicklen)) + nick )
	sequence+=1
	#print_line ( COLOR2 + "-!- watch challenge from " + B_COLOR2 + str(nick) + END + "\n")

def pdu_join(channel):
	global sequence,CHANNEL
	CHANNEL=channel
	channellen = len(channel)
	pdulen = 4 + 4 + 4 + channellen
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x05" + pad(chr(channellen)) + channel )
	sequence+=1

def pdu_status(status):
	global sequence
	pdulen = 4+4+4
	if (status==0):
		special.append("BACK")
	elif (status==1):
		special.append("AWAY")
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + pad(chr(status)))
	sequence+=1

def pdu_list():
	global sequence
	pdulen = 4+4
	special.append("LIST")
	s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x03')
	sequence+=1

def process_user_input():
	while 1:

		print_line(PROMPT)

		if (len(special)>0):
			time.sleep(0.1)
			continue

		command = command_queue.get()

		if (command != "" and not command.startswith("/")):
			pdu_chat(command)

		# send a challenge request
		elif (command.startswith("/challenge ")):
			nick = command[11:]
			if (nick == USERNAME):
				if (autochallenge==0):
					print_line ( COLOR3 + "-!- guru meditation: you can't challenge yourself" + END + "\n")
			else:
				pdu_challenge(nick)

		# accept a challenge request (initiated by peer)
		elif (command.startswith("/accept ")):
			nick = command[8:]
			if nick in list(challengers):
				pdu_accept(nick)
			else:
				print_line ( COLOR3 + "-!- " + B_COLOR3 + str(nick) + COLOR3 + " hasn't challenged you" + END + "\n")

		# if there's only one incoming challenge request, allow the user to type /accept without parameters (no need to specify nick)
		elif (command == "/accept"):
			if (len(challengers)==1):
				for nick in list(challengers):
					pdu_accept(nick)
					break
			elif(len(challengers)>1):
				print_line ( COLOR3 + "-!- there's more than one incoming challenge request: you need to specify the nick." + END + "\n")
			else:
				print_line ( COLOR3 + "-!- you have not received any challenge request" + END + "\n")

		# decline a challenge request (initiated by peer)
		elif (command.startswith("/decline ")):
			nick = command[9:]
			if nick in list(challengers):
				pdu_decline(nick)
			else:
				print_line ( COLOR3 + "-!- " + B_COLOR3 + str(nick) + COLOR3 + " hasn't challenged you" + END + "\n")

		# /decline without parameters declines all incoming challenge requests
		elif (command == "/decline"):
			if (len(challengers)==0):
				print_line ( COLOR3 + "-!- you have not received any challenge request" + END + "\n")
			for nick in list(challengers):
				pdu_decline(nick)

		# cancel an ongoing challenge request (initiated by us)
		elif (command.startswith("/cancel ")):
			nick = command[8:]
			if nick in list(challenged):
				pdu_cancel(nick)
			else:
				print_line ( COLOR3 + "-!- you aren't challenging " + B_COLOR3 + str(nick) + END + "\n")

		# /cancel without parameters: cancel all ongoing challenge requests
		elif (command == "/cancel"):
			if (len(challenged)==0 and autochallenge==0):
				print_line ( COLOR3 + "-!- all outgoing challenge requests cleared" + END + "\n")
			for nick in list(challenged):
				pdu_cancel(nick)

		# watch an ongoing match
		elif (command.startswith("/watch ")):
			nick = command[7:]
			pdu_watch(nick)

		# choose channel
		elif (command.startswith("/join ")):
			channel = command[6:]
			pdu_join(channel)

		# set away status (can't be challenged)
		elif (command == "/away"):
			pdu_status(1)

		# return back from away (can be challenged)
		elif (command == "/back" or command == "/available"):
			pdu_status(0)

		# view channel motd
		elif (command == "/motd"):
			pdu_motd()

		# list channels
		elif (command == "/list"):
			pdu_list()

		# list users
		elif (command.startswith("/users ") or command.startswith("/whois ") or command=="/who" or command=="/users" or command=="/names" or command.startswith("/names ")):
			pdu_users(command)

		# unknown command
		elif (command != ""):
			print_line ( COLOR3 + "-!- unknown command: " + B_COLOR3 + str(command) + END + "\n")

		command_queue.task_done()
		print_line(PROMPT)

def datathread():
	BUFFER = ''
	while 1:

		try:
			data = s.recv(4096)
		except:
			BUFFER=''
			print_line ( COLOR4 + "-!- connection lost. Reconnecting." + END + "\n")
			reset_autocomplete()
			connect_sequence(6)

		if (DEBUG>1): print_line ( COLOR4 + "    HEX0: " + repr(data) + END + "\n")

		data = BUFFER + data
		try:
			pdulen = int(data[0:4].encode('hex'), 16)
		except ValueError:
			pdulen = 0
			BUFFER=''
			data = ''
			if (DEBUG>0): print_line (COLOR1 + "*** Unparseable PDU: " + repr(data) + END + "\n")
			print_line ( COLOR4 + "-!- connection lost. Reconnecting." + END + "\n")
			reset_autocomplete()
			connect_sequence(5)

		if (DEBUG>2): print_line ( COLOR2 + "PDULEN: " + str(pdulen) + " LEN_DATA: " + str(len(data)) + END + "\n")
		#DATA: [ 4-byte pdulen ][ pdulen-byte pdu ]

		while (len(data) > pdulen+4):
			if (DEBUG>2): print_line ( COLOR1 + "(*) PDULEN: " + str(pdulen) + " LEN_DATA: " + str(len(data)) + END + "\n")
			pdulen = int(data[0:4].encode('hex'), 16)
			pdu = data[0:pdulen+4]
			if (DEBUG>2): print_line ( COLOR1 + "(*) PAR0: " + repr(data) + END + "\n")
			parse(pdu)
			if (len(data[pdulen+4:]) > 4):
				data = data[pdulen+4:]
				pdulen = int(data[0:4].encode('hex'), 16)

		if (len(data) == pdulen+4):
			if (DEBUG>2): print_line ( COLOR5 + "    PDULEN: " + str(pdulen) + " LEN_DATA: " + str(len(data)) + END + "\n")
			if (DEBUG>2): print_line ( COLOR5 + "    PAR1: " + repr(data) + END + "\n")
			parse(data)
			BUFFER = ''

		if (len(data) < pdulen+4):
			BUFFER = BUFFER + data

		print_line(PROMPT)
		time.sleep(1)
		print_line(PROMPT)

def showverbose():
	text = COLOR3 + "-!- " + COLOR0 + "current VERBOSE=" + B_COLOR0 + str(VERBOSE) + COLOR0, 
	if (VERBOSE==0): text+= "only showing challenge requests/replies" + END,
	if (VERBOSE==1): text+= "showing challenges + chat" + END,
	elif (VERBOSE==2): text+= "showing challenges + chat + new matches" + END,
	elif (VERBOSE==3): text+= "showing challenges + chat + new matches + status changes" + END,
	text+="\n",
	print_line(' '.join(text))

def connect_sequence(retries):
	global s, sequence

	servers=('ggpo.net','69.10.128.134','69.10.128.133','69.10.128.132','ggpo.net','69.10.128.134')

	connected=False
	count=0

	try:
		s.close()
	except:
		pass

	while (connected!=True and count < retries):
		server=servers[count]
		count+=1
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((server, 7000))
			connected=True
		except Exception, e:
			print_line ( COLOR1 + "-!- [" + str(count) + "/" + str(retries) + "] Can't connect to GGPO server: " + str(e) + END + "\n")
			time.sleep(5)
			connected=False

	if (connected==False):
		if (LOGFILE!=""):
			try:
				logfile.close()
			except:
				pass
		os._exit(1)

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
	pdu_join(CHANNEL)

	# should we start away by default?
	if (STARTAWAY == 1): command_queue.put("/away")

if __name__ == '__main__':

	DEBUG=0 # values: 0,1,2,3

	special=[]

	# initialize defaults for config
	USERNAME=""
	PASSWORD=""
	CHANNEL="lobby"
	INSTALLDIR=""
	VERBOSE=3
	STARTAWAY=0
	TIMESTAMP=0
	SMOOTHING=1  # from 0 to 10, 0: jerky, 1: default, 10: laggy
	CHECKLATENCY=0
	LOGFILE=""

	COLOR0 = '\033[0;38m' # GRAY
	COLOR1 = '\033[0;31m' # RED
	COLOR2 = '\033[0;32m' # GREEN
	COLOR3 = '\033[0;33m' # YELLOW
	COLOR4 = '\033[0;34m' # BLUE
	COLOR5 = '\033[0;35m' # MAGENTA
	COLOR6 = '\033[0;36m' # CYAN
	B_COLOR0 = '\033[1;30m'
	B_COLOR1 = '\033[1;31m'
	B_COLOR2 = '\033[1;32m'
	B_COLOR3 = '\033[1;33m'
	B_COLOR4 = '\033[1;34m'
	B_COLOR5 = '\033[1;35m'
	B_COLOR6 = '\033[1;36m'

	notifyjoin=1
	NOTIFY=set()
	IGNORE=set()

	END = '\033[0;m'
	PROMPT = "\rggpo" + COLOR1 + "> " + END

	print_line ( COLOR3 + "-!- " + COLOR4 + "GGPO.PY CLIENT " + B_COLOR4 + "VERSION " + VERSION + END + "\n")
	print_line ( COLOR3 + "-!- " + COLOR4 + "(c) 2014 Pau Oliva Fora (" + B_COLOR4 + "pof" + COLOR4 + "). Licensed under GPLv2+." + END + "\n")

	# check for updates
	try:
		response = urllib2.urlopen('https://raw.github.com/poliva/ggpo/master/VERSION')
		version = response.read().strip()
		if (version != VERSION):
			print_line ( COLOR3 + "-!- " + B_COLOR4 + "new version " + B_COLOR3 + version + B_COLOR4 + " available at " + B_COLOR3 + "http://poliva.github.io/ggpo/" + END + "\n")
	except:
		pass

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
			print_line ( COLOR1 + "-!- ERROR: cannot write to config file at " + CONFIGFILE + END + "\n")
			os._exit(1)

		print_line ( "\n" + COLOR4 + "-!- it looks like you're running ggpo for the first time, let's configure it!" + END + "\n")
		print_line ( COLOR4 + "-!- this quick setup will create a config file at:\n\t" + COLOR2 + CONFIGFILE + END + "\n")

		# try to guess install directory:

		# directory of the script being run
		dirtest1 = os.path.dirname(os.path.abspath(__file__))
		# current working directory
		dirtest2 = os.getcwd()

		if (os.path.isfile(dirtest1+"/ggpofba.exe")):
			INSTALLDIR=dirtest1
			print_line( "\n" + COLOR4 + "-!- found GGPO install dir at: " + COLOR2 + INSTALLDIR + END + "\n")
		elif (os.path.isfile(dirtest2+"/ggpofba.exe")):
			INSTALLDIR=dirtest2
			print_line( "\n" + COLOR4 + "-!- found GGPO install dir at: " + COLOR2 + INSTALLDIR + END + "\n")
		else:
			print_line( "\n" + COLOR4 + "-!- please specify the full path where you have unziped the official GGPO client" + END + "\n")
			try:
				INSTALLDIR = raw_input("\r" + COLOR4 + "GGPO INSTALLDIR:" + END + " ")
			except KeyboardInterrupt:
				print_line( "\n" + COLOR1 + "-!- ^C interrupted." + END + "\n")
				configfile.close()
				os.unlink(CONFIGFILE)
				os._exit(1)

		if not os.path.isfile(INSTALLDIR+"/ggpofba.exe"):
			print_line ( COLOR3 + "-!- WARNING: cannot find ggpofba.exe in " + INSTALLDIR + END + "\n")

		print_line( "\n" + COLOR4 + "-!- please specify your GGPO credentials" + END + "\n")
		try:
			USERNAME = raw_input("\r" + COLOR4 + "GGPO USERNAME:" + END + " ")
			PASSWORD = raw_input("\r" + COLOR4 + "GGPO PASSWORD:" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + COLOR1 + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

		print_line( "\n" + COLOR4 + "-!- please specify your GGPO game room, if unsure type 'lobby'" + END + "\n")
		try:
			CHANNEL = raw_input("\r" + COLOR4 + "GGPO CHANNEL:" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + COLOR1 + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

		if not os.path.isfile(INSTALLDIR+"/ROMs/" + CHANNEL + ".zip") and CHANNEL!="lobby":
			print_line ( COLOR3 + "-!- WARNING: cannot find " + CHANNEL + ".zip in " + INSTALLDIR + "/ROMs/" + END + "\n")

		LOGDIR = INSTALLDIR + "/log"
		if not os.path.exists(LOGDIR):
			os.makedirs(LOGDIR)
		LOGFILE = LOGDIR + "/ggpo.log"

		configfile.write("#GGPO configuration file\n")
		configfile.write("USERNAME=" + USERNAME + "\n")
		configfile.write("PASSWORD=" + PASSWORD + "\n")
		configfile.write("CHANNEL=" + CHANNEL + "\n")
		configfile.write("INSTALLDIR=" + INSTALLDIR + "\n")
		configfile.write("VERBOSE=3\n")
		configfile.write("STARTAWAY=0\n")
		configfile.write("TIMESTAMP=0\n")
		configfile.write("SMOOTHING=1\n")
		configfile.write("CHECKLATENCY=0\n")
		configfile.write("#LOGFILE=" + LOGFILE + "\n")
		configfile.write("\n# comma separated list of friends\n")
		configfile.write("NOTIFY=\n")
		configfile.write("\n# comma separated list of enemies\n")
		configfile.write("IGNORE=\n")
		configfile.write("\n#color profile\n")
		configfile.write("COLOR0=[0;38m\n")
		configfile.write("COLOR1=[0;31m\n")
		configfile.write("COLOR2=[0;32m\n")
		configfile.write("COLOR3=[0;33m\n")
		configfile.write("COLOR4=[0;34m\n")
		configfile.write("COLOR5=[0;35m\n")
		configfile.write("COLOR6=[0;36m\n")
		configfile.write("B_COLOR0=[1;30m\n")
		configfile.write("B_COLOR1=[1;31m\n")
		configfile.write("B_COLOR2=[1;32m\n")
		configfile.write("B_COLOR3=[1;33m\n")
		configfile.write("B_COLOR4=[1;34m\n")
		configfile.write("B_COLOR5=[1;35m\n")
		configfile.write("B_COLOR6=[1;36m\n")
		configfile.close()
		LOGFILE=""

		print_line( "\n" + COLOR4 + "-!- thank you, configuration is completed!" + END + "\n")
		try:
			raw_input("\r" + COLOR4 + "-!- press ENTER to connect for the fist time" + END + " ")
		except KeyboardInterrupt:
			print_line( "\n" + COLOR1 + "-!- ^C interrupted." + END + "\n")
			configfile.close()
			os.unlink(CONFIGFILE)
			os._exit(1)

	try:
		configfile = open(CONFIGFILE, "r")
	except IOError:
		print_line ( COLOR1 + "-!- ERROR: cannot read config file at " + CONFIGFILE + END + "\n")
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
		if (line.startswith("TIMESTAMP=")): TIMESTAMP=int(line[10:].strip())
		if (line.startswith("SMOOTHING=")): SMOOTHING=int(line[10:].strip())
		if (line.startswith("CHECKLATENCY=")): CHECKLATENCY=int(line[13:].strip())
		if (line.startswith("LOGFILE=")): LOGFILE=line[8:].strip()
		if (line.startswith("NOTIFY=")):
			notifycfg = line[7:].strip()
			if (len(notifycfg)>0):
				NOTIFY=set(notifycfg.split(","))
		if (line.startswith("IGNORE=")):
			ignorecfg = line[7:].strip()
			if (len(ignorecfg)>0):
				IGNORE=set(ignorecfg.split(","))
		if (line.startswith("COLOR0=")): COLOR0='\033'+line[7:].strip()
		if (line.startswith("COLOR1=")): COLOR1='\033'+line[7:].strip()
		if (line.startswith("COLOR2=")): COLOR2='\033'+line[7:].strip()
		if (line.startswith("COLOR3=")): COLOR3='\033'+line[7:].strip()
		if (line.startswith("COLOR4=")): COLOR4='\033'+line[7:].strip()
		if (line.startswith("COLOR5=")): COLOR5='\033'+line[7:].strip()
		if (line.startswith("COLOR6=")): COLOR6='\033'+line[7:].strip()
		if (line.startswith("B_COLOR0=")): B_COLOR0='\033'+line[9:].strip()
		if (line.startswith("B_COLOR1=")): B_COLOR1='\033'+line[9:].strip()
		if (line.startswith("B_COLOR2=")): B_COLOR2='\033'+line[9:].strip()
		if (line.startswith("B_COLOR3=")): B_COLOR3='\033'+line[9:].strip()
		if (line.startswith("B_COLOR4=")): B_COLOR4='\033'+line[9:].strip()
		if (line.startswith("B_COLOR5=")): B_COLOR5='\033'+line[9:].strip()
		if (line.startswith("B_COLOR6=")): B_COLOR6='\033'+line[9:].strip()
	configfile.close()

	print_line ( COLOR3 + "-!- " + COLOR4 + "if you are lost type '/help' and press enter." + END + "\n")

	FBA = INSTALLDIR + "/ggpofba.sh"
	MP3 = INSTALLDIR + "/assets/challenger-comes.mp3"

	u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
	try:
		u.bind(('0.0.0.0', 6009))
	except socket.error:
		print_line ( COLOR3 + "-!- WARNING: cannot bind to port udp/6009" + END + "\n")

	t = Thread(target=pingcheck)
	t.daemon = True
	t.start()

	command_queue = Queue()

	AUTOCOMPLETE=[]
	reset_autocomplete()
	s=''
	connect_sequence(4)

	command=""
	challengers=set()
	challenged=set()
	users_option=""
	playing_against=''
	pinglist=[]
	userlist=[]

	available_users=[]
	away_users=[]
	playing_users=[]

	autochallenge=0
	challengewa=set()

	t2 = Thread(target=datathread)
	t2.daemon = False
	t2.start()

	t3 = Thread(target=process_user_input)
	t3.daemon = False
	t3.start()

	if (LOGFILE != ""):
		logfile = open(LOGFILE, "a")

	while 1:

		# we want to treat '/' as part of the word
		readline.set_completer_delims(' \t')
		if 'libedit' in readline.__doc__:
			readline.parse_and_bind("bind ^I rl_complete")
		else:
			readline.parse_and_bind("tab: complete")
		readline.set_completer(complete)

		command = raw_input(PROMPT)
		command = command.strip(' \t\n\r')

		if (command == "/help"):
			print_line ( COLOR3 + "-!- " + COLOR4 + "available commands:" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/challenge [<nick>]\tsend a challenge request to <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/autochallenge <ms|off>\tauto-challenge anyone with ping < <ms>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/challengewa <nick>\tauto-challenge when <nick> becomes available" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/xchallenge <nick>\tcross challenge <nick> to fix assetion errors" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/cancel [<nick>]\t\tcancel an ongoing challenge request to <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/accept [<nick>]\t\taccept a challenge request initiated by <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/decline [<nick>]\tdecline a challenge request initiated by <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/watch <nick>\t\twatch the game that <nick> is currently playing" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/whois <nick>\t\tdisplay information about the user <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/whowas <nick>\t\tinfo about <nick> that is no longer connected" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/ping <nick>\t\tsends a PING to <nick> and displays lag in ms" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/notify [<nick>]\t\tget a notification when <nick> is available" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/ignore [<nick>]\t\tignore chat messages & challenges from <nick>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/join <channel>\t\tjoin the chat/game room <channel>" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/users [<modifier>]\tlist all users in the current channel" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/names [<modifier>]\tsame as /users but only display nickname" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "         modifier: 'available', 'away' or 'playing'" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/list \t\t\tlist all available channels or chat/game rooms" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/motd \t\t\tview the channel welcome text" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/away \t\t\tset away status (you can't be challenged)" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/back \t\t\tset available status (you can be challenged)" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/clear \t\t\tclear the screen" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/play [<P1|P2> <ip address>] play against cpu or p2p-netplay" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/verbose [<flag>]\tchange verbosity level" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "           flag:'0' challenges, '1' chat, '2' match, '3' status" + END + "\n")
			print_line ( COLOR3 + "-!- " + COLOR4 + "/quit \t\t\tdisconnect from ggpo server" + END + "\n")

		elif (command.startswith("/whowas ")):
			nick = command[8:]
			found = print_user_long(nick,"whowas")
			if (found==1):
				print_line ( COLOR3 + "-!- " + COLOR0 + "end of WHOWAS" + END + "\n")
			else:
				print_line ( COLOR3 + "-!- there was no such nick " + B_COLOR3 + nick + END + "\n")

		# hidden command, not present in /help
		elif (command.startswith("/debug ")):
			debug = command[7:]
			if (debug == "0"): DEBUG=0
			elif (debug == "1"): DEBUG=1
			elif (debug == "2"): DEBUG=2
			elif (debug == "3"): DEBUG=3
			else: print_line ( COLOR3 + "-!- possible values are /debug [<0|1|2|3>]" + END + "\n")
		elif (command == "/debug"):
			print_line ( COLOR3 + "-!- " + COLOR0 + "DEBUG: " + str(DEBUG) + END + "\n")

		elif (command.startswith("/verbose ")):
			verbose = command[9:]
			if (verbose == "0"): VERBOSE=0
			elif (verbose == "1"): VERBOSE=1
			elif (verbose == "2"): VERBOSE=2
			elif (verbose == "3"): VERBOSE=3
			else: print_line ( COLOR3 + "-!- possible values are /verbose [<0|1|2|3>]" + END + "\n")
			showverbose()

		elif (command == "/verbose"):
			showverbose()

		elif (command == "/challenge"):
			if (len(challenged)==0):
				print_line ( COLOR3 + "-!- not challenging anyone. Usage: /challenge <nick>" + END + "\n")
			else:
				text= COLOR3 + "-!- " + COLOR0 + "challenging:",
				for nick in challenged:
					text+= "["+ B_COLOR2 + nick + COLOR0 + "]",
				text+=END+"\n",
				print_line(' '.join(text))

		elif (command.startswith("/ping ")):
			nick = command[6:]
			user = get_user_info(nick)
			ip = user[1]
			port = user[5]
			check_ping(nick,ip,port)
			# sleep 1sec to collect ping data
			time.sleep(1)
			ping = get_ping_msec(nick)
			if (ping != 0):
				print_line ( COLOR2 + "-!- PING reply from " + B_COLOR2 + nick + COLOR2 + ": [" + B_COLOR2 + str(int(ping)) + COLOR2 + " ms]" + END + "\n")
			else:
				print_line ( COLOR3 + "-!- PING timeout from " + B_COLOR3 + nick + END + "\n")

		elif (command.startswith("/challengewa ")):
			nick = command[13:]
			if (nick == "off"):
				challengewa=set()
				print_line ( COLOR2 + "-!- challengewa list cleared" + END + "\n")
			elif (nick!=USERNAME):
				found=False
				for user in available_users:
					if (nick==user[0]):
						command_queue.put("/challenge " + nick)
						found=True
						break
				if (found==False):
					challengewa.add(nick)
					print_line ( COLOR2 + "-!- " + B_COLOR2 + nick + COLOR2 + " will be automatically challenged when available" + END + "\n")
					print_line ( COLOR2 + "-!- type '/challengewa off' to disable it" + END + "\n")
			elif (nick==USERNAME):
				print_line ( COLOR3 + "-!- guru meditation: you can't challenge yourself" + END + "\n")

		elif (command=="/challengewa"):
			if (len(challengewa)==0):
				print_line ( COLOR3 + "-!- usage: /challengewa <nick>" + END + "\n")
			else:
				text= COLOR3 + "-!- " + COLOR0 + "challenging when available:",
				for nick in challengewa:
					text+= "["+ B_COLOR2 + nick + COLOR0 + "]",
				text+=END+"\n",
				print_line(' '.join(text))

		elif (command.startswith("/autochallenge ")):
			value = command[15:]
			try:
				autochallenge=int(value)
			except ValueError:
				if (value == "off"):
					disable_autochallenge()
				else:
					print_line ( COLOR3 + "-!- usage: /autochallenge <max-ping-msec|off>" + END + "\n")
				autochallenge=0
				continue

			print_line ( COLOR2 + "-!- autochallenge is set to [" + B_COLOR2 + str(autochallenge) + COLOR2 +" ms]. type '/autochallenge off' to disable it" + END + "\n")
			for user in available_users:
				ping = int(user[8])
				if (ping > 0 and ping < autochallenge):
					command_queue.put("/challenge " + user[0])

		elif (command == "/autochallenge"):
			if (autochallenge==0):
				print_line ( COLOR3 + "-!- autochallenge is off. Usage: /autochallenge <max-ping-msec|off>" + END + "\n")
			else:
				print_line ( COLOR2 + "-!- autochallenge is set to [" + B_COLOR2 + str(autochallenge) + COLOR2 +" ms]. Type '/autochallenge off' to disable it" + END + "\n")

		elif (command.startswith("/xchallenge ")):
			nick = command[12:]
			command_queue.put("/challenge " + nick)
			command_queue.put("/accept " + nick)

		elif (command.startswith("/notify ")):
			nick = command[8:]
			if (nick == "off"):
				NOTIFY=set()
				print_line ( COLOR2 + "-!- notify list cleared" + END + "\n")
			elif (nick!=USERNAME):
				NOTIFY.add(nick)
			elif (nick==USERNAME):
				print_line ( COLOR3 + "-!- guru meditation: you can't be notified of yourself" + END + "\n")

		elif (command == "/notify"):
			if(len(NOTIFY)==0):
				print_line ( COLOR3 + "-!- no users in notify list. Usage: /notify <nick>" + END + "\n")
			else:
				text= COLOR3 + "-!- " + COLOR0 + "notify:",
				for nick in NOTIFY:
					text+= "["+ B_COLOR2 + nick + COLOR0 + "]",
				text+=END+"\n",
				print_line(' '.join(text))

		elif (command.startswith("/ignore ")):
			nick = command[8:]
			if (nick == "off"):
				IGNORE=set()
				print_line ( COLOR2 + "-!- ignore list cleared" + END + "\n")
			elif (nick!=USERNAME):
				IGNORE.add(nick)
			elif (nick==USERNAME):
				print_line ( COLOR3 + "-!- guru meditation: you can't ignore yourself" + END + "\n")

		elif (command == "/ignore"):
			if(len(IGNORE)==0):
				print_line ( COLOR3 + "-!- no users in ignore list. Usage: /ignore <nick>" + END + "\n")
			else:
				text= COLOR3 + "-!- " + COLOR0 + "ignore:",
				for nick in IGNORE:
					text+= "["+ B_COLOR2 + nick + COLOR0 + "]",
				text+=END+"\n",
				print_line(' '.join(text))

		elif (command == "/play"):
			args = [FBA, CHANNEL]
			try:
				FNULL = open(os.devnull, 'w')
				call(args, stdout=FNULL, stderr=FNULL)
				FNULL.close()
				print_line ( COLOR2 + "-!- launching ggpofba to play against the CPU" + END + "\n")
			except OSError:
				print_line ( COLOR1 + "-!- ERROR: can't execute " + FBA + END + "\n")

		elif (command.startswith("/play ")):
			params = command[6:].split(' ')
			if (len(params)!=2):
				print_line ( COLOR3 + "-!- usage: /play [<P1|P2> <ip address>]" + END + "\n")
				continue
			player=params[0]
			ipaddr=params[1]
			px = re.compile("^[p|P](1|2)$")
			if (not px.match(player)):
				print_line ( COLOR3 + "-!- usage: /play [<P1|P2> <ip address>]" + END + "\n")
				continue
			args = [FBA, CHANNEL, player, ipaddr]
			try:
				FNULL = open(os.devnull, 'w')
				call(args, stdout=FNULL, stderr=FNULL)
				FNULL.close()
				print_line ( COLOR2 + "-!- launching ggpofba for p2p-netplay as " + player.upper() + " against " + ipaddr + END + "\n")
			except OSError:
				print_line ( COLOR1 + "-!- ERROR: can't execute " + FBA + END + "\n")

		# hidden abreviation, not present in autocomplete
		elif (command == "/n"): command_queue.put("/names")

		elif (command == "/watch" or command=="/whois" or command=="/whowas" or command=="/ping" or command=="/xchallenge"):
			print_line ( COLOR3 + "-!- usage: "+ command +" <nick>" + END + "\n")

		elif (command == "/join"):
			print_line ( COLOR3 + "-!- usage: /join <channel>" + END + "\n")

		elif (command == "/clear"):
			call(['clear'])

		elif (command == "/quit"):
			s.close()
			u.close()
			#call(['reset'])
			print_line ( COLOR3 + "-!- " + COLOR4 + "have a nice day :)" + END + "\n")
			if (LOGFILE!=""): logfile.close()
			os._exit(0)
		else:
			command_queue.put(command)

		command_queue.join()
