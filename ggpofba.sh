#!/bin/bash

# ggpofba wrapper script for version 0.2.96.74 (bundled with ggpo)
# (c)2013-2014 Pau Oliva Fora (@pof)

# This resets pulseaudio on Linux because otherwise FBA hangs on my computer (WTF!?).
# For best results run 'winecfg' and check the option to "Emulate a virtual desktop"
# under the Graphics tab. I've it set to 1152x672 for best full screen aspect ratio.


CONFIGFILE=~/.config/ggpo/ggpo.config
source ${CONFIGFILE} 2>/dev/null

if [ -z "${INSTALLDIR}" ]; then
	echo "-!- Please launch ggpo.py to create your config file"
	exit 1
fi

FBA="${INSTALLDIR}/ggpofba.exe"
if [ ! -e ${FBA} ]; then
	echo "-!- cannot find ${INSTALLDIR}/ggpofba.exe"
	exit 1
fi

function show_usage() {
	echo "USAGE: $0 <ROM> [<P1|P2> <IP>]"
	exit 1
}

IP=""
echo ${1+"$@"} |grep "quark:" >/dev/null
if [ $? -eq 1 ]; then

	ROM=$1
	if [ $# -ne 1 ]; then
		PLAYER=$2
		IP=$3
		if [ -z "${IP}" ]; then show_usage ; fi
		echo "${PLAYER}" |egrep "^[P|p](1|2)$" >/dev/null
		if [ $? -ne 0 ]; then show_usage ; fi
		p=$(echo ${PLAYER} |cut -c 2)
		p=$(( $p - 1 ))
		if [ $p -eq 0 ]; then port1=7000 ; port2=7001 ; fi
		if [ $p -eq 1 ]; then port1=7001 ; port2=7000 ; fi
	fi

	if [ ! -f "${INSTALLDIR}/ROMs/${ROM}.zip" ]; then
		echo "ERROR: Can't find ${INSTALLDIR}/ROMs/${ROM}.zip"
		show_usage
	fi
fi

OS=$(uname -s)
case "${OS}" in
	"Darwin")
		echo "-!- starting the real ggpofba"
		if [ -z "${IP}" ]; then
			/Applications/Wine.app/Contents/Resources/bin/wine ${FBA} ${1+"$@"} &
		else
			/Applications/Wine.app/Contents/Resources/bin/wine ${FBA} quark:direct,${ROM},${port1},${IP},${port2},${p} &
		fi
	;;

	"Linux")
		# check if there are multiple instances running
		tot=$(ps ax |grep ggpofba.exe |grep quark |wc -l)

		# first instance resets pulseaudio, others don't
		if [ $tot -eq 0 ]; then
			VOL=$(pacmd dump |grep "^set-sink-volume" |tail -n 1 |awk '{print $3}')
			echo "-!- resetting pulseaudio"
			/usr/bin/pulseaudio -k
			/usr/bin/pulseaudio --start
		fi

		echo "-!- starting the real ggpofba"
		if [ -z "${IP}" ]; then
			/usr/bin/wine ${FBA} ${1+"$@"} &
		else
			/usr/bin/wine ${FBA} quark:direct,${ROM},${port1},${IP},${port2},${p} &
		fi

		if [ $tot -eq 0 ]; then
			sleep 1s
			echo "-!- restoring volume value"
			/usr/bin/pactl set-sink-volume 0 ${VOL}
		fi
	;;
esac
