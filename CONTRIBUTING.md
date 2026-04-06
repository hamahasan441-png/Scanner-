# Contributing to ATOMIC Framework

Thank you for your interest in contributing to the ATOMIC Framework! This guide will help you get started.

## Development Setup

### Prerequisites
- Python 3.10 or higher
- Git

### Clone & Install

```bash
git clone https://github.com/hamahasan441-png/Scanner-.git
cd Scanner-
pip install -r requirements.txt
pip install pytest pytest-cov flake8 black mypy
```

### Verify Setup

```bash
python main.py --check-deps
```

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=core --cov=modules --cov=utils --cov=web --cov-report=term-missing

# Run a specific test file
python -m pytest tests/test_sqli_module.py -v

# Run tests matching a pattern
python -m pytest tests/ -v -k "graphql"
```

## Code Style

- Follow PEP 8 with a max line length of 150 characters
- Use `flake8` for linting: `flake8 . --max-line-length=150 --max-complexity=15`
- Use `black` for formatting (optional): `black --line-length 150 .`

## Project Structure

```
core/       — Engine components (orchestrator, AI, reporter, Burp tools)
modules/    — Attack and scanning modules (one per vulnerability type)
utils/      — Utility libraries (requester, crawler, evasion, database)
web/        — Flask web dashboard and REST API
tests/      — Unit and integration tests (one test file per module)
config.py   — Payloads, configuration constants, MITRE mapping
main.py     — CLI entry point
```

## Adding a New Attack Module

1. **Create the module file** in `modules/` (e.g., `modules/my_vuln.py`):

```python
from config import Colors

class MyVulnModule:
    name = "My Vulnerability"
    vuln_type = 'my_vuln'

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.verbose = engine.config.get('verbose', False)

    def test(self, url, method, param, value):
        """Test a parameter for the vulnerability."""
        # Your testing logic here
        pass

    def test_url(self, url):
        """Optional: URL-level test (e.g., for header-based checks)."""
        pass
```

2. **Register the module** in `core/engine.py` `_load_modules()`:

```python
'my_vuln': ('modules.my_vuln', 'MyVulnModule'),
```

3. **Add CLI flag** in `main.py`:

```python
parser.add_argument('--my-vuln', action='store_true',
                   help='Enable my vulnerability detection')
```

4. **Add to module config** in `main.py` (in the `modules = { ... }` dict):

```python
'my_vuln': args.my_vuln or args.full,
```

5. **Add payloads** to `config.py` `Payloads` class if needed.

6. **Write tests** in `tests/test_my_vuln_module.py`.

7. **Update CI** in `.github/workflows/ci.yml` to validate the import.

## Writing Tests

Tests use `unittest.mock` to avoid real network requests. Follow the pattern in existing test files:

```python
import unittest
from unittest.mock import MagicMock, patch

class TestMyVulnModule(unittest.TestCase):
    def setUp(self):
        self.engine = MagicMock()
        self.engine.config = {'verbose': False}
        self.engine.requester = MagicMock()
        self.engine.findings = []

    def test_something(self):
        from modules.my_vuln import MyVulnModule
        mod = MyVulnModule(self.engine)
        # ... test logic
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes with tests
4. Ensure all tests pass: `python -m pytest tests/ -v`
5. Ensure linting passes: `flake8 . --select=E9,F63,F7,F82`
6. Open a pull request with a clear description

## Reporting Issues

When reporting bugs, please include:
- Python version (`python --version`)
- Operating system
- Steps to reproduce
- Expected vs. actual behavior
- Error output / traceback

## Code of Conduct

- Be respectful and constructive
- This tool is for **authorized security testing only**
- Do not contribute features designed to facilitate unauthorized access
- Follow responsible disclosure practices
