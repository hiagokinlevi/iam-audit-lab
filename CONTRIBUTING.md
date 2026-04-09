# Contributing to iam-audit-lab

Thank you for your interest in contributing. This document explains how to set up a development
environment and submit contributions.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- [uv](https://github.com/astral-sh/uv) (recommended) or pip + venv
- Cloud provider credentials for manual testing (optional — unit tests use mocks)

### Setup

```bash
# Clone the repository
git clone https://github.com/hiagokinlevi/iam-audit-lab.git
cd iam-audit-lab

# Create virtual environment and install dependencies
uv sync --dev

# Copy environment configuration
cp .env.example .env
```

### Running Tests

```bash
# Run all tests (uses mocks — no cloud credentials required)
uv run pytest tests/ -v

# Run with coverage
uv run pytest tests/ -v --cov=providers --cov=analyzers --cov=schemas --cov-report=term-missing
```

### Code Style

```bash
uv run ruff check .
uv run ruff format .
uv run mypy providers/ analyzers/ schemas/
```

## Contribution Workflow

1. **Fork** the repository on GitHub.
2. **Create a branch**: `git checkout -b feat/your-feature-name`
3. **Write tests** for any new functionality. PRs without tests will not be merged.
4. **Ensure all tests pass** and the linter reports no errors.
5. **Commit** with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/).
6. **Open a pull request** against `main`.

## Adding a New Provider

To add support for a new cloud provider:

1. Create `providers/<provider>/identity_collector.py` following the pattern of existing collectors.
2. Implement `collect_identities(config: dict) -> list[IdentityRecord]` as the public interface.
3. Add unit tests in `tests/` using mocks (never require real credentials for tests).
4. Add the provider to `cli/main.py`.
5. Document the required permissions in `README.md`.

## Pull Request Guidelines

- One feature or fix per PR.
- Ensure no credentials or sensitive data appear in test fixtures.
- Update documentation for any changed behavior.
- Reference related issues with `Closes #issue_number`.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
