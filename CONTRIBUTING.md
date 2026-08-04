# Contributing to AuthDiff

Thanks for helping build AuthDiff! This project favours **deterministic,
provable** detection over heuristics — keep that principle central to any change.

## Development setup

```bash
git clone https://github.com/bdalzyzr116-rgb/authdiff-bugbounty
cd authdiff-bugbounty
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,fast]"
pre-commit install
pytest
```

## Pre-commit

Create `.pre-commit-config.yaml` at the repo root with:

```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.5.7
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.1
    hooks:
      - id: mypy
        additional_dependencies: ["types-PyYAML"]
        args: ["authdiff"]
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.9
    hooks:
      - id: bandit
        args: ["-r", "authdiff"]
```

Then run `pre-commit install`.

## Standards

- **Typed**: `mypy --strict` must pass.
- **Linted**: `ruff check authdiff` and `ruff format`.
- **Tested**: add tests for every change; coverage gate is 90%.
- **Docstrings**: Google-style on public functions/classes.
- **Async-first**: network code uses `asyncio` and the Scope Governor.

## Adding an oracle

Implement the `Oracle` protocol (`evaluate(obs) -> Finding | None`). Proven
oracles must carry a canary or invariant witness. Register via `OracleRegistry`
or expose an `authdiff.oracles` entry point in your package.

## Adding an input parser

Add a module under `authdiff/inputs/` returning `ObservedRequest` objects and
wire it into `inputs/registry.py` with content sniffing.
