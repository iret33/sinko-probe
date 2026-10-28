.PHONY: install test lint run-local compare

install:
	pip install -e ".[dev]"

lint:
	ruff check src/ tests/

test:
	pytest -v

run-local:
	sinko-probe run --server 127.0.0.1 --html sinko_audit.html

compare:
	sinko-probe compare -t Sinko=192.168.1.2 -t CloudflareFamily=1.1.1.3
