#!/bin/bash
# ATOMIC Framework v7.0 - Setup Script for Termux
# Usage: bash setup.sh

echo "=========================================="
echo "  ATOMIC Framework v7.0 - Setup"
echo "  Termux Edition"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running in Termux
if [ -d "/data/data/com.termux" ]; then
    echo -e "${BLUE}[*] Termux detected${NC}"
    IS_TERMUX=1
else
    echo -e "${BLUE}[*] Standard Linux detected${NC}"
    IS_TERMUX=0
fi

# Update packages
echo -e "${BLUE}[*] Updating packages...${NC}"
if [ $IS_TERMUX -eq 1 ]; then
    pkg update -y && pkg upgrade -y
else
    sudo apt-get update && sudo apt-get upgrade -y
fi

# Install system dependencies
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
if [ $IS_TERMUX -eq 1 ]; then
    pkg install -y python clang libffi openssl git libxml2 libxslt
else
    sudo apt-get install -y python3 python3-pip python3-dev clang libffi-dev openssl git libxml2-dev libxslt1-dev
fi

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p reports
mkdir -p shells
mkdir -p wordlists
mkdir -p logs

# Make main.py executable
echo -e "${BLUE}[*] Setting permissions...${NC}"
chmod +x main.py

# Create symlink for global access
echo -e "${BLUE}[*] Creating shortcut...${NC}"
if [ -d "$HOME/.local/bin" ]; then
    ln -sf "$(pwd)/main.py" "$HOME/.local/bin/atomic"
    echo -e "${GREEN}[+] Shortcut created: atomic${NC}"
fi

# Create launcher script
cat > atomic.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")" || exit
python main.py "$@"
EOF
chmod +x atomic.sh

echo ""
echo "=========================================="
echo -e "${GREEN}[+] Setup completed!${NC}"
echo "=========================================="
echo ""
echo "Usage:"
echo "  python main.py -t https://target.com"
echo "  ./atomic.sh -t https://target.com --full"
echo ""
echo "Examples:"
echo "  python main.py -t https://example.com              # Basic scan"
echo "  python main.py -t https://example.com --full       # Full scan"
echo "  python main.py -t https://example.com --shell      # Try shell upload"
echo "  python main.py -t https://example.com --dump       # Dump database"
echo "  python main.py --list-scans                        # List scans"
echo "  python main.py --shell-manager                     # Manage shells"
echo ""
echo -e "${YELLOW}⚠️  FOR AUTHORIZED TESTING ONLY ⚠️${NC}"
echo ""
