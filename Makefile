.PHONY: help install test lint fuzz mutate invariants scenarios corpus report doctor demo build docker run clean docker-up docker-down docker-fuzz all

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

install:  ## Install in development mode
	pip install -e .[dev]

test:  ## Run all tests
	pytest --tb=short -q

lint:  ## Run linter
	ruff check .

fuzz:  ## Run synthetic fuzzer (1000 requests)
	orchesis fuzz --policy examples/production_policy.yaml --count 1000 --save-bypasses

mutate:  ## Run mutation engine (500 mutations)
	orchesis mutate --policy examples/production_policy.yaml --count 500

invariants:  ## Verify runtime invariants
	orchesis invariants --policy examples/production_policy.yaml

scenarios:  ## Run adversarial scenarios
	orchesis scenarios --policy examples/production_policy.yaml

corpus:  ## Show corpus stats
	orchesis corpus --stats

report:  ## Generate reliability report
	orchesis reliability-report

doctor:  ## Check installation health
	orchesis doctor --policy examples/production_policy.yaml

demo:  ## Run E2E demo
	python run_e2e_demo.py

build:  ## Build Python package
	python -m build
	twine check dist/orchesis-*

docker:  ## Build Docker image
	docker build -t orchesis:latest .

docker-up:  ## Start all services
	docker compose up -d

docker-down:  ## Stop all services
	docker compose down

docker-fuzz:  ## Run fuzzer in Docker
	docker compose --profile testing run --rm orchesis-fuzzer

clean:  ## Clean build artifacts
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

all: lint test invariants  ## Full CI check
