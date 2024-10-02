#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change the directory to the script's location
cd "$SCRIPT_DIR"

# Set up a Python virtual environment
python3 -m venv ./linux_venv

# Activate the virtual environment
source ./linux_venv/bin/activate

# Install dependencies from requirements.txt
pip install -r requirements.txt

# Deactivate the virtual environment
deactivate
