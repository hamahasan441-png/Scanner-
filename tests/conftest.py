"""Pytest configuration — ensures the project root is on sys.path."""

import os
import sys

# Add project root so that imports resolve without pip install
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
