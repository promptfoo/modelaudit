#!/bin/bash
set -e

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up Poetry for modelaudit...${NC}"

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    echo -e "${BLUE}Poetry not found. Installing Poetry...${NC}"
    curl -sSL https://install.python-poetry.org | python3 -
    # Add Poetry to PATH (you may need to restart your terminal)
    export PATH="$HOME/.local/bin:$PATH"
else
    echo -e "${GREEN}Poetry is already installed.${NC}"
fi

# Create a new virtual environment with Poetry
echo -e "${BLUE}Creating virtual environment and installing dependencies...${NC}"
poetry install

# Optionally install dependencies for specific scanners
echo -e "${BLUE}Would you like to install optional dependencies? (y/n)${NC}"
read -n 1 choice
echo ""

if [[ $choice == "y" || $choice == "Y" ]]; then
    echo -e "${BLUE}Select extra dependencies to install:${NC}"
    echo "1) TensorFlow (for TF SavedModel scanning)"
    echo "2) h5py (for Keras H5 scanning)"
    echo "3) PyTorch (for PyTorch model scanning)"
    echo "4) All of the above"
    echo "0) None"
    read -n 1 extra_choice
    echo ""
    
    case $extra_choice in
        1)
            echo -e "${BLUE}Installing TensorFlow dependencies...${NC}"
            poetry install --extras "tensorflow"
            ;;
        2)
            echo -e "${BLUE}Installing h5py dependencies...${NC}"
            poetry install --extras "h5"
            ;;
        3)
            echo -e "${BLUE}Installing PyTorch dependencies...${NC}"
            poetry install --extras "pytorch"
            ;;
        4)
            echo -e "${BLUE}Installing all optional dependencies...${NC}"
            poetry install --extras "all"
            ;;
        *)
            echo -e "${GREEN}No extra dependencies selected.${NC}"
            ;;
    esac
fi

echo -e "${GREEN}Setup complete!${NC}"
echo -e "${BLUE}To activate the virtual environment, run:${NC}"
echo "  poetry shell"
echo -e "${BLUE}Or to run a command within the virtual environment:${NC}"
echo "  poetry run modelaudit scan /path/to/model" 
