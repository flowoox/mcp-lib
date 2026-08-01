.PHONY: install test lint check compose up down logs

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

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f --tail=200
