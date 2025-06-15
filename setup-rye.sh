#!/bin/bash
set -e

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Setting up Rye for modelaudit...${NC}"

# Check if Rye is installed
if ! command -v rye &> /dev/null; then
    echo -e "${BLUE}Rye not found. Installing Rye...${NC}"
    curl -sSf https://rye-up.com/get | bash
    # Source the profile to add Rye to PATH
    source ~/.profile 2>/dev/null || source ~/.bashrc 2>/dev/null || true
    export PATH="$HOME/.rye/shims:$PATH"
    echo -e "${YELLOW}Please restart your terminal or run 'source ~/.profile' to update your PATH${NC}"
else
    echo -e "${GREEN}Rye is already installed.${NC}"
fi

# Initialize the project (sync dependencies)
echo -e "${BLUE}Syncing dependencies with Rye...${NC}"
rye sync

# Show installed tools
echo -e "${BLUE}Available development tools:${NC}"
echo "  rye run ruff check     - Run linting"
echo "  rye run ruff format    - Format code"
echo "  rye run mypy           - Type checking"
echo "  rye run pytest         - Run tests"
echo "  rye run pytest --cov  - Run tests with coverage"

# Optionally install dependencies for specific scanners
echo -e "${BLUE}Would you like to install optional dependencies? (y/n)${NC}"
read -n 1 choice
echo ""

if [[ $choice == "y" || $choice == "Y" ]]; then
    echo -e "${BLUE}Select extra dependencies to install:${NC}"
    echo "1) TensorFlow (for TF SavedModel scanning)"
    echo "2) h5py (for Keras H5 scanning)"
    echo "3) PyTorch (for PyTorch model scanning)"
    echo "4) YAML (for YAML configuration files)"
    echo "5) All of the above"
    echo "0) None"
    read -n 1 extra_choice
    echo ""
    
    case $extra_choice in
        1)
            echo -e "${BLUE}Installing TensorFlow dependencies...${NC}"
            rye sync --features tensorflow
            ;;
        2)
            echo -e "${BLUE}Installing h5py dependencies...${NC}"
            rye sync --features h5
            ;;
        3)
            echo -e "${BLUE}Installing PyTorch dependencies...${NC}"
            rye sync --features pytorch
            ;;
        4)
            echo -e "${BLUE}Installing YAML dependencies...${NC}"
            rye sync --features yaml
            ;;
        5)
            echo -e "${BLUE}Installing all optional dependencies...${NC}"
            rye sync --features all
            ;;
        *)
            echo -e "${GREEN}No extra dependencies selected.${NC}"
            ;;
    esac
fi

echo -e "${GREEN}Setup complete!${NC}"
echo -e "${BLUE}Key Rye commands:${NC}"
echo "  rye run modelaudit scan /path/to/model  - Run the CLI tool"
echo "  rye run python                          - Start Python REPL"
echo "  rye run pytest                          - Run tests"
echo "  rye shell                              - Activate virtual environment"
echo "  rye sync                               - Sync dependencies"
echo "  rye add <package>                      - Add a dependency"
echo "  rye add --dev <package>               - Add a dev dependency" 