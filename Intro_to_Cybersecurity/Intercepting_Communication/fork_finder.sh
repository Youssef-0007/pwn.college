#!/bin/bash
# fork_finder_v2.sh - Accounts for 1-second process lifetime

MAX_FORKS=0
FAILED=0

# Test in increments of 10
for batch in {10..2000..10}; do
  echo "Testing $batch connections..."
  
  # Launch batch
  start_time=$(date +%s)
  for i in $(seq 1 $batch); do
    nc -z 10.0.0.2 31337 &
    ((MAX_FORKS++))
  done
  
  # Wait exactly 1 second (server's process lifetime)
  while (( $(date +%s) - start_time < 1 )); do
    sleep 0.1
  done
  
  # Check failures
  if wait -n 2>/dev/null; then
    echo "  - Batch $batch: Success"
  else
    ((FAILED++))
    echo "  - Batch $batch: Failed (max approaching)"
    (( FAILED >= 2 )) && break
  fi
  
  pkill -f "nc 10.0.0.2 31337"
done

echo "Estimated max forks: $((MAX_FORKS - 10))"
