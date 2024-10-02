#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change the directory to the script's location
cd "$SCRIPT_DIR"

# Print the current directory (for debugging)
echo "Current directory: $SCRIPT_DIR"

# Activate the virtual environment
source ./linux_venv/bin/activate

# Print the Python executable location (for debugging)
echo "Using Python: $(which python3)"

# Check if bson is installed in the virtual environment (for debugging)
pip list | grep bson

# Execute main.py with all passed arguments
python3 ./src/main.py "$@"
