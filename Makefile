# ATOMIC Framework v10.0 - Makefile
# Common development and deployment shortcuts.

.PHONY: help install dev test lint format type-check security-scan run web docker clean

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install pytest pytest-cov flake8 black mypy bandit pip-audit

test: ## Run all tests
	python -m pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	python -m pytest tests/ -v --tb=short --ignore=tests/integration

test-integration: ## Run integration tests only
	python -m pytest tests/integration/ -v --tb=short

test-coverage: ## Run tests with coverage report
	python -m pytest tests/ -v --cov=core --cov=modules --cov=utils --cov=web \
		--cov-report=term-missing --cov-report=html

lint: ## Run flake8 linter
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 . --count --exit-zero --max-complexity=15 --max-line-length=150 --statistics

format: ## Format code with black
	black --line-length 150 .

type-check: ## Run mypy type checker
	mypy core/ modules/ utils/ web/ --ignore-missing-imports

security-scan: ## Run security scanners (bandit + pip-audit)
	bandit -r core/ modules/ utils/ web/ -ll --exit-zero
	pip-audit --strict --exit-zero || true

run: ## Run a basic scan (set TARGET=https://example.com)
	python main.py -t $(TARGET)

web: ## Start the web dashboard
	python main.py --web

docker: ## Build and run with Docker
	docker compose up --build

clean: ## Remove generated files
	rm -rf reports/*.html reports/*.json reports/*.csv reports/*.pdf
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	rm -rf .pytest_cache htmlcov .coverage
	rm -rf *.egg-info dist build
