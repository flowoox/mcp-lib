.PHONY: install test lint check compose build build-soulseek build-traxx up down logs

install:
	python -m pip install -e '.[dev]'

test:
	pytest -q

lint:
	ruff check src tests

check: lint test
	python -m compileall -q src

compose:
	docker compose config

build: build-soulseek build-traxx

build-soulseek:
	docker build --target soulseek -t mcp-soulseek:local .

build-traxx:
	docker build --target traxx -t mcp-traxx:local .

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=200
