#!/bin/bash

PORT=31337

# Ping sweep first to find live hosts
echo "Scanning for live hosts in 10.0.0.0/24..."
live_hosts=()
for i in {1..254}; do
    ip="10.0.0.$i"
    [ "$ip" == "10.0.0.1" ] && continue  # Skip self

    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        echo "Host $ip is alive"
        live_hosts+=("$ip")
    fi
done

echo "Found ${#live_hosts[@]} live hosts"

# Try connecting to each live host on target port
for ip in "${live_hosts[@]}"; do
    echo "Attempting connection to $ip:$PORT"
    if timeout 1 bash -c "echo 'PING_TEST' | nc -w 1 $ip $PORT"; then
        echo -e "\nSUCCESS: Connected to $ip:$PORT"
        echo "Starting interactive session (Ctrl+C to exit)..."
        nc "$ip" "$PORT"
        exit 0
    fi
done

echo "No hosts responded on port $PORT"
exit 1
