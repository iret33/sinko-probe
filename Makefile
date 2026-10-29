.PHONY: install lint format test check run-local compare docker

install:
	python -m pip install -e ".[dev]"

lint:
	python -m ruff check .
	python -m ruff format --check .

format:
	python -m ruff format .
	python -m ruff check --fix .

test:
	python -m pytest -v

check: lint test

run-local:
	sinko-probe run --server 127.0.0.1 --html sinko_audit.html

compare:
	sinko-probe compare -t Sinko=192.168.1.2 -t CloudflareFamily=1.1.1.3

docker:
	docker build -t sinko-probe .
