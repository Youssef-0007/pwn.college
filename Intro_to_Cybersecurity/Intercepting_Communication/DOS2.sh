#!/bin/bash

for i in {1..100}; do
	nc -v 10.0.0.2 31337 &
done
