#!/bin/bash
# ATOMIC Framework v8.0 - Setup Script
# Usage: bash setup.sh

set -e

echo "=========================================="
echo "  ATOMIC Framework v8.0 - Setup"
echo "  Ultimate Edition"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

fail() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

# Check if running in Termux
if [ -d "/data/data/com.termux" ]; then
    echo -e "${BLUE}[*] Termux detected${NC}"
    IS_TERMUX=1
else
    echo -e "${BLUE}[*] Standard Linux detected${NC}"
    IS_TERMUX=0
fi

# Verify Python is available
if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    fail "Python is not installed. Please install Python 3.9+ first."
fi

PYTHON=$(command -v python3 || command -v python)
PY_VERSION=$($PYTHON -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
echo -e "${BLUE}[*] Using Python ${PY_VERSION}${NC}"

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
    pkg install -y python clang libffi openssl git
else
    sudo apt-get install -y python3 python3-pip python3-dev clang libffi-dev openssl git libxml2-dev libxslt1-dev
fi

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
$PYTHON -m pip install --upgrade pip || fail "pip upgrade failed"
$PYTHON -m pip install -r requirements.txt || fail "Failed to install Python dependencies"

# Install optional C-extension packages (may fail on Termux)
echo -e "${BLUE}[*] Installing optional dependencies...${NC}"
for opt_dep in lxml cryptography paramiko; do
    echo -e "${BLUE}[*] Trying ${opt_dep}...${NC}"
    if $PYTHON -m pip install "$opt_dep" --only-binary :all: -q 2>/tmp/atomic_opt_dep.log; then
        echo -e "${GREEN}[+] ${opt_dep} installed${NC}"
    else
        echo -e "${YELLOW}[!] ${opt_dep} skipped (no pre-built wheel available — not required for core functionality)${NC}"
    fi
done
rm -f /tmp/atomic_opt_dep.log

# Create necessary directories
echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p reports shells wordlists logs

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
echo "  python main.py -t https://target.com              # Basic scan"
echo "  python main.py -t https://target.com --full       # Full scan (all modules)"
echo "  python main.py -t https://target.com --evasion insane  # Max evasion"
echo "  python main.py --web                              # Launch web dashboard"
echo "  python main.py --web --web-port 8080              # Dashboard on port 8080"
echo ""
echo "Quick Install (Python only):"
echo "  pip install -r requirements.txt && python main.py --web"
echo ""
echo -e "${YELLOW}⚠️  FOR AUTHORIZED TESTING ONLY ⚠️${NC}"
echo ""
