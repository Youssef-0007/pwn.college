#!/bin/bash

# Loop through all files starting with solution_ and ending with .py
for file in solution_*.py; do
    # Extract the number part
    number=$(echo "$file" | sed -E 's/solution_([0-9]+)\.py/\1/')
    
    # Construct the new filename
    new_file="level_${number}.py"
    
    # Rename the file
    mv "$file" "$new_file"
done

echo "Renaming complete!"
