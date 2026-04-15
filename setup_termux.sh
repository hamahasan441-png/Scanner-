#!/data/data/com.termux/files/usr/bin/bash
# ──────────────────────────────────────────────────────────────────────
# ATOMIC FRAMEWORK — One-command Termux Setup
# Downloads dependencies, installs llama-cpp-python, and fetches
# the Qwen2.5-7B GGUF model so everything works out of the box.
#
# Usage:
#   chmod +x setup_termux.sh && ./setup_termux.sh
# ──────────────────────────────────────────────────────────────────────
set -e

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ATOMIC FRAMEWORK — Termux Installer                       ║"
echo "║  Installs Python, dependencies, llama-cpp-python & Qwen2.5 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ── 1. System packages ───────────────────────────────────────────────
echo "[1/6] Installing system packages..."
pkg update -y
pkg upgrade -y
pkg install -y python clang libffi openssl git wget cmake ninja

# ── 2. Python packages ───────────────────────────────────────────────
echo "[2/6] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# ── 3. llama-cpp-python (Qwen2.5-7B inference engine) ────────────────
echo "[3/6] Installing llama-cpp-python..."
# Termux uses clang by default; set env vars for C/C++ compilation
export CC=clang
export CXX=clang++
pip install llama-cpp-python --no-cache-dir 2>&1 || {
    echo "[!] llama-cpp-python failed to install from pip."
    echo "    Trying from source..."
    pip install llama-cpp-python --no-cache-dir --force-reinstall \
        --config-settings='cmake.args=-DGGML_BLAS=OFF' 2>&1 || {
        echo "[!] Installation failed. You can try manually:"
        echo "    pip install llama-cpp-python"
        echo "    The scanner will work without AI features."
    }
}

# ── 4. Download Qwen2.5-7B GGUF model ────────────────────────────────
echo "[4/6] Downloading Qwen2.5-7B-Instruct model (~4.7 GB)..."
python main.py --download-model

# ── 5. Verify installation ────────────────────────────────────────────
echo "[5/6] Verifying installation..."
python -c "
import sys
print(f'Python: {sys.version}')
try:
    import requests; print(f'requests: {requests.__version__}')
except ImportError:
    print('requests: NOT INSTALLED')
try:
    import llama_cpp; print(f'llama-cpp-python: installed')
except ImportError:
    print('llama-cpp-python: NOT INSTALLED (AI features disabled)')
from core.local_llm import is_model_downloaded
if is_model_downloaded():
    print('Qwen2.5-7B model: downloaded')
else:
    print('Qwen2.5-7B model: NOT downloaded (run: python main.py --download-model)')
print('All core dependencies OK')
"

# ── 6. Done ───────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✓ Setup complete!                                         ║"
echo "║                                                            ║"
echo "║  Quick start:                                              ║"
echo "║    python main.py -t https://target.com --full             ║"
echo "║    python main.py -t https://target.com --local-llm        ║"
echo "║    python main.py -t https://target.com --point-to-point   ║"
echo "║                                                            ║"
echo "║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
