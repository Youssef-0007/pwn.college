#!/bin/bash
MAX_CONNECTIONS=1000
DELAY=$(awk "BEGIN {print 1/$MAX_CONNECTIONS}")

while true; do
	for((i = 0; i < MAX_CONNECTIONS; i++)); do
		nc -v 10.0.0.2 31337 > /dev/null &
		sleep $DELAY
		if((i % 100 == 0)); then
			sleep 0.1
		fi
	done
	#sleep $DELAY
	#wait # wait untile all the background jobs finish (~1 sec)
done
