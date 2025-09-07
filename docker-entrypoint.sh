#!/bin/bash

# Docker entrypoint script for ModelAudit full image
# This allows the container to run both modelaudit commands and python scripts

# If the first argument is exactly "python", run python with remaining args
if [[ "$1" == "python" ]]; then
    shift  # Remove "python" from arguments
    exec python "$@"
fi

# If the first argument is a python flag, run python
if [[ "$1" == "-c" ]] || [[ "$1" == "-m" ]]; then
    exec python "$@"
fi

# If no arguments or first argument looks like a modelaudit option, run modelaudit
if [[ $# -eq 0 ]] || [[ "$1" == "--"* ]] || [[ "$1" == "-"* ]] || [[ "$1" == "scan" ]]; then
    exec modelaudit "$@"
fi

# For file paths or other arguments, assume it's a scan command
exec modelaudit "$@"