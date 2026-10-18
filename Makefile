.PHONY: setup dev demo eval test lint
setup:
	uv sync --frozen

dev:
	uv run agentshield serve

demo:
	uv run agentshield demo

eval:
	uv run agentshield eval

test:
	uv run pytest -q

lint:
	uv run ruff check .
