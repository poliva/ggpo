#!/bin/bash

# ggpofba wrapper script for version 0.2.96.74 (bundled with ggpo)
# (c)2013-2014 Pau Oliva Fora (@pof)

# This resets pulseaudio because otherwise FBA hangs on my computer (WTF!?).
# For best results run 'winecfg' and check the option to "Emulate a virtual desktop"
# under the Graphics tab. I've it set to 1152x672 for best full screen aspect ratio.

# Change this to the path of ggpofba.exe on your system:
FBA="/opt/ggpo/ggpofba.exe"

# check if there are multiple instances running
tot=$(ps ax |grep ggpofba.exe |grep quark |wc -l)

# first instance resets pulseaudio, others don't
if [ $tot -eq 0 ]; then
	echo "-!- resetting pulseaudio"
	VOL=$(pacmd dump |grep "^set-sink-volume" |tail -n 1 |awk '{print $3}')
	/usr/bin/pulseaudio -k
	/usr/bin/pulseaudio --start
fi

echo "-!- starting the real ggpofba"
wine ${FBA} ${1+"$@"} &

if [ $tot -eq 0 ]; then
	sleep 1s
	echo "-!- restoring volume value"
	/usr/bin/pactl set-sink-volume 0 ${VOL}
fi
