#!/bin/bash
# Setup script for VPN Latency Checker
# Creates virtual environment, installs dependencies, and activates it

set -e  # Exit on error

VENV_DIR="venv"
REQUIREMENTS_FILE="requirements.txt"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}VPN Latency Checker - Environment Setup${NC}"
echo "=========================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
    echo -e "${GREEN}Virtual environment created at $VENV_DIR${NC}"
else
    echo -e "${GREEN}Virtual environment already exists at $VENV_DIR${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --quiet --upgrade pip

# Install dependencies if requirements.txt exists
if [ -f "$REQUIREMENTS_FILE" ]; then
    echo -e "${YELLOW}Installing dependencies from $REQUIREMENTS_FILE...${NC}"
    pip install --quiet -r "$REQUIREMENTS_FILE"
    echo -e "${GREEN}Dependencies installed${NC}"
else
    echo -e "${YELLOW}Warning: $REQUIREMENTS_FILE not found. Skipping dependency installation.${NC}"
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${GREEN}Virtual environment is now active.${NC}"
echo ""
echo "To activate this environment in the future, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "To deactivate, run:"
echo "  deactivate"

