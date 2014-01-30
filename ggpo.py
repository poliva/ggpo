#!/usr/bin/python

# very rudimentary ggpo command line client
# protocol reverse engineered from the official adobe air client
# (c) 2014 Pau Oliva Fora

import socket
import string
import re
import sys
import os
import signal

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

TIMEOUT=3
USERNAME="pof"
PASSWORD="XXXXXXXX"
CHANNEL="ssf2t"

VERBOSE=1  # set to 1 to see join/leave/play messages
DEBUG=0

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('ggpo.net', 7000))

s.send('\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1d\x00\x00\x00\x01')
s.send("\x00\x00\x00\x30\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00" + chr(len(USERNAME)) + USERNAME + "\x00\x00\x00" + chr(len(PASSWORD)) + PASSWORD + "\x00\x00\x17\x79")
s.send('\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x03')
s.send("\x00\x00\x00\x11\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x00" + chr(len(CHANNEL)) + CHANNEL + "\x00\x00\x00\x08\x00\x00\x00\x09\x00\x00\x00\x02\x00\x00\x00\x08\x00\x00\x00\x0a\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x0b\x00\x00\x00\x02")
s.send('\x00\x00\x00\x08\x00\x00\x00\x08\x00\x00\x00\x04')
s.send('\x00\x00\x00\x08\x00\x00\x00\x09\x00\x00\x00\x04')
s.send('\x00\x00\x00\x08\x00\x00\x00\x0a\x00\x00\x00\x02')
s.send('\x00\x00\x00\x08\x00\x00\x00\x0b\x00\x00\x00\x04')

# away 
s.send('\x00\x00\x00\x0c\x00\x00\x00\x0c\x00\x00\x00\x06\x00\x00\x00\x01')

sequence=0xd

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

	if (line != None):
		print line
		msglen = len(line)
		pdulen = msglen + 12
		s.send("\x00\x00\x00" + chr(pdulen) + "\x00\x00\x00" + chr(sequence) + "\x00\x00\x00\x07\x00\x00\x00" + chr(msglen) + line)
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

	if (VERBOSE==1):
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\n','JOIN01: ', data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00.','JOIN02: ', data)	# Enter & change state (away/available)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\n','PLAY01: ', data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00.','PLAY02: ', data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n','JOIN03: ', data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00.','LEAVE: ', data)	# leave/part
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00.\x00\x00\x00.\x00\x00\x00\n','JOIN04: ',data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00.\x00\x00\x00.\x00\x00\x00.','JOIN05: ',data)
	else:
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00.\x00\x00\x00.\x00\x00\x00\n.*','',data)
		data = re.sub('\x00\x00.*\xff\xff\xff\xfd\x00\x00\x00.\x00\x00\x00.\x00\x00\x00.*','',data)
		data = re.sub('\n.*','',data)

	# when someone challenges you:
	data = re.sub('\x00\x00.*\xff\xff\xff\xfc\x00\x00\x00.', 'CHALLENGE: ', data)
	if "CHALLENGE" in data:
		data = re.sub('\x00\x00\x00\x05', ' @ ', data);

	# cancel challenge:
	data = re.sub('\x00\x00.*\xff\xff\xff\xef\x00\x00\x00.', 'CANCELED CHALLENGE: ', data)


	# put <> between nick names (this must be done the latest):
	data = re.sub('\x00\x00\x00.*\xff\xff\xff\xfe\x00\x00\x00\n','<', data)
	data = re.sub('\x00\x00.*\xff\xff\xff\xfe\x00\x00\x00\n', '<', data)
	data = re.sub('\x00\x00.*\xff\xff\xff\xfe\x00\x00\x00.', '<', data)
	data = re.sub('\x00\x00.*\xff\xff\xff\xfe\x00\x00\x00', '<', data)
	data = re.sub('.*\xff\xff\xff\xfe\x00\x00\x00\n', '<', data)
	data = re.sub('\x00\x00..\xff\xff\xff\xfe\x00\x00\x00\n', '<', data)
	data = re.sub('\x00\x00..\xff\xff\xff\xfe\x00\x00\x00.', '<', data)
	data = re.sub('\x00\x00\x00\n', '> ', data)
	data = re.sub('\x00\x00..','> ', data)

	# fix 3 >>>
	data = re.sub('> > > ', ' * ', data)
	data = re.sub('> $', '', data)

	if (data!='' and data.startswith("<")==False and "CHALLENGE" not in data and "JOIN" not in data and "LEAVE" not in data and "PLAY" not in data):
		print "HEX1-ORIG: ",repr(orig)
		print "HEX2-DATA: ",repr(data)
	if (data!=''):
		filtered_data = filter(lambda x: x in string.printable, data)
		print filtered_data

s.close()


### TODO: ability to challenge someone
# 4th byte = length of message
# 8th byte = sequence number
# 12th byte == 08 == challenge someone
# 12th byte == 1c == cancel challenge
# 16th byte == length of nickname
