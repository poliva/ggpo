#!/usr/bin/python

# very rudimentary ggpo command line client
# protocol reverse engineered from the official adobe air client
# (c) 2014 Pau Oliva Fora

import socket
import string
import re
import sys
import signal
from subprocess import call

USERNAME="pof"
PASSWORD="XXXXXXXX"
CHANNEL="ssf2t"

DEBUG=0
TIMEOUT=3

SPECIAL=""

def interrupted(signum, frame):
	"called when read times out"
	#print 'interrupted!'
signal.signal(signal.SIGALRM, interrupted)

def input():
	try:
		#print "> ",
		foo = sys.stdin.readline()
		foo = foo.strip(' \t\n\r')
		return foo
	except:
		# timeout
		return

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
		print "<" + str(nick) + "> " + str(msg)

	# state changes (away/back/playing)
	elif (action == "\xff\xff\xff\xfd"):

		unk1 = cmd[8:12]
		unk2 = cmd[12:16]

		nicklen = int(cmd[16:20].encode('hex'),16)
		nick = cmd[20:20+nicklen]


		if (unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x00"): print "LEAVE: " + str(nick)


#ACTION: '\xff\xff\xff\xfd' + DATA: '\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x06WoRKeR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e88.226.227.119\x00\x00\x00"\x00\x00\x00&\x00\x00\x00\x08Nevsehir\x00\x00\x00\x02TR\x00\x00\x00\x06Turkey\x00\x00\x17y\x00\x00\x00\x01\x00\x00\x00\x06WoRKeR\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e88.226.227.119\x00\x00\x00"\x00\x00\x00&\x00\x00\x00\x08Nevsehir\x00\x00\x00\x02TR\x00\x00\x00\x06Turkey\x00\x00\x17y\x00\x00\x00\x01\x00\x00\x00\x06djkeco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r188.77.72.142\xff\xff\xff\xfc\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x02ES\x00\x00\x00\x05Spain\x00\x00\x17y\x00\x00\x00\x01\x00\x00\x00\x06djkeco\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r188.77.72.142\xff\xff\xff\xfc\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x02ES\x00\x00\x00\x05Spain\x00\x00\x17y'
#ACTION: '\xff\xff\xff\xfd' + DATA: '\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\tCronobest\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c87.12.238.77\x00\x00\x00\x0c\x00\x00\x00+\x00\x00\x00\x07Perugia\x00\x00\x00\x02IT\x00\x00\x00\x05Italy\x00\x00\x17y\x00\x00\x00\x01\x00\x00\x00\tCronobest\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c87.12.238.77\x00\x00\x00\x0c\x00\x00\x00+\x00\x00\x00\x07Perugia\x00\x00\x00\x02IT\x00\x00\x00\x05Italy\x00\x00\x17y\x00\x00\x00\x00\x00\x00\x00\tCronobest'


		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x00"):
		#if (unk1 == "\x00\x00\x00\x03" and unk2 == "\x00\x00\x00\x01"):
		#if (unk1 == "\x00\x00\x00\x04" and unk2 == "\x00\x00\x00\x01"):
		#if (unk1 == "\x00\x00\x00\x05" and unk2 == "\x00\x00\x00\x01\):

		elif ((unk1 == "\x00\x00\x00\x01" and unk2 == "\x00\x00\x00\x01") or (unk1 == "\x00\x00\x00\x02" and unk2 == "\x00\x00\x00\x01")):

			state = int(cmd[20+nicklen:20+nicklen+4].encode('hex'),16)  # 1=away, 0=back, 2=play

			if (state==2):
				nick2len = int(cmd[24+nicklen:28+nicklen].encode('hex'),16)
				nick2 = cmd[28+nicklen:28+nicklen+nick2len]

				print "NEW GAME: " + str(nick) + " vs " + str(nick2)

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

				print "STATE: [",
				if (state == 0): print "back",
				if (state == 1): print "away",
				print "] nick=" + str(nick) + " ip=" + str(ip) + " city=" + str(city) + " cc=" + cc + " country=" + str(country)

		else:
			print "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4])

	# challenge
	elif (action == "\xff\xff\xff\xfc"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		channellen = int(cmd[12+nicklen:12+nicklen+4].encode('hex'),16)
		channel = cmd[16+nicklen:16+nicklen+channellen]

		print "INCOMING CHALLENGE FROM " + str(nick) + "@ " + channel

	# cancel challenge
	elif (action == "\xff\xff\xff\xef"):

		nicklen = int(cmd[8:12].encode('hex'),16)
		nick = cmd[12:12+nicklen]

		print "CANCEL CHALLENGE " + str(nick)


	elif (action == "\xff\xff\xff\xff"):
		print "> Connected ok!"

	# unknown action
	else:
		if (SPECIAL == "" ):
			print "ACTION: " + repr(action) + " + DATA: " + repr(cmd[8:pdulen+4])
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

		print "\n" + str(channel) + " || " + str(topic)
		print str(msg) + "\n"
		SPECIAL=""

	elif (SPECIAL=="AWAY"):
		SPECIAL=""

	elif (SPECIAL=="BACK"):
		SPECIAL=""

	elif (SPECIAL=="LIST"):
		parselist(cmd)
		SPECIAL=""

	elif (SPECIAL=="USERS"):
		parseusers(cmd)
		SPECIAL=""

	else:
		print "SPECIAL=" + SPECIAL + " + DATA: " + repr(cmd[8:pdulen+4])

def parseusers(cmd):

	pdulen = int(cmd[0:4].encode('hex'), 16)

	#print repr(cmd[8:pdulen+4])

	i=16
	#while (i<pdulen):
	while (i<len(cmd)-4):

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

		unk3 = cmd[i:i+4]
		i=i+4

		if (status==0): print nick + " (" + ip + ") " + city + " " + country + " [available]"
		elif (status==1): print nick + " (" + ip + ") " + city + " " + country + " [away]"
		elif (status==2): print nick + " (" + ip + ") " + city + " " + country + " [playing against " + p2nick + "]"
		else: print nick + " (" + ip + ") " + city + " " + country + " [Unknown status: " + str(status) + "]"

def parselist(cmd):

	pdulen = int(cmd[0:4].encode('hex'), 16)

	i=12
	#while (i<pdulen):
	while (i<len(cmd)-4):
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
		print str(name1) + " - " + str(name2) + " - " + str(name3)

if __name__ == '__main__':

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('ggpo.net', 7000))

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

	while 1:
		# set alarm
		signal.alarm(TIMEOUT)
		line = input()
		# disable the alarm after success
		signal.alarm(0)

		#line = sys.stdin.readline()
		#line = os.fdopen(sys.stdin.fileno(), 'r', 30)
		#line = raw_input('> ')
		#if not line: break

		if (line != None and not line.startswith("/")):
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
			pdulen = 4 + 4 + 4 + nicklen + 4 + channellen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x08" + pad(chr(nicklen)) + nick + pad(chr(channellen)) + CHANNEL)
			sequence=sequence+1

		# cancel an ongoing challenge request
		if (line != None and line.startswith("/cancel ")):
			nick = line[8:]
			nicklen = len(nick)
			pdulen = 4 + 4 + 4 + nicklen
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + "\x00\x00\x00\x1c" + pad(chr(nicklen)) + nick )
			sequence=sequence+1

		# set away status (can't be challenged)
		if (line == "/away"):
			pdulen = 4+4+4
			SPECIAL="AWAY"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x01')
			sequence=sequence+1

		# return back from away (can be challenged)
		if (line == "/back"):
			pdulen = 4+4+4
			SPECIAL="BACK"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x06' + '\x00\x00\x00\x00')
			sequence=sequence+1

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
		if (line == "/users"):
			pdulen = 4+4
			SPECIAL="USERS"
			s.send( pad(chr(pdulen)) + pad(chr(sequence)) + '\x00\x00\x00\x04')
			sequence=sequence+1

		if (line == "/quit"):
			s.close()
			sys.exit(0)

		signal.alarm(TIMEOUT)
		data = readdata()
		signal.alarm(0)
		if not data: continue

		orig = data

		if (DEBUG==1):
			print "HEX: ",repr(data)

		parse(data)

		if ("quark:" in data):
			index = data.find("quark:")
			cmd = data[index:]
			# WARNING: cmd is unsanitized
			args = ['/opt/ggpo/ggpofba.exe', cmd]
			call(args)

	s.close()
