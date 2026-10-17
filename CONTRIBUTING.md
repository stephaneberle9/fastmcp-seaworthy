# Contributing <!-- omit in toc -->

Thank you for your interest in contributing to `fastmcp-seaworthy`! This document
provides guidelines for setting up a development environment, making changes,
and testing them locally before pushing to GitHub.

- [Development Setup](#development-setup)
  - [Prerequisites](#prerequisites)
  - [Clone and install](#clone-and-install)
- [Code Quality](#code-quality)
  - [Enable automatic execution on git commit](#enable-automatic-execution-on-git-commit)
  - [Manual execution](#manual-execution)
- [Testing](#testing)
- [Contributing Changes](#contributing-changes)
- [Release Process](#release-process)
  - [Testing a release first](#testing-a-release-first)
- [Building Packages Locally](#building-packages-locally)
- [Dependency Management](#dependency-management)

## Development Setup

### Prerequisites

- [Python 3.10](https://www.python.org/downloads) or later
- [uv](https://docs.astral.sh/uv/) — fast Python package manager

### Clone and install

```bash
git clone https://github.com/stephaneberle9/fastmcp-seaworthy.git
cd fastmcp-seaworthy
uv sync
```

## Code Quality

This project uses `pre-commit` hooks for static checks to maintain high code
quality standards:

| Hook | Purpose |
| ---- | ------- |
| `validate-pyproject` | Project configuration validation |
| `prettier` | JSON and YAML formatting |
| `ruff-check` | Python linting (with auto-fix) |
| `ruff-format` | Python code formatting |
| `ty check` | Modern type checking for Python |
| `codespell` | Common spelling error detection |

### Enable automatic execution on git commit

```bash
uv run pre-commit install
```

### Manual execution

```bash
# Run all checks on all files
uv run pre-commit run --all-files

# Run individual tools
uv run ruff format          # Code formatting
uv run ruff check --fix     # Linting with auto-fix
uv run ty check             # Type checking
uv run deptry .             # Declared vs. imported dependencies
```

## Testing

```bash
# Run all tests with coverage
uv run pytest

# Run a specific test file
uv run pytest tests/test_serve.py

# Run with verbose output
uv run pytest -v

# Show only a coverage summary (skip HTML report)
uv run pytest --cov-report=term-missing --no-cov-on-fail
```

Coverage is collected from `src/fastmcp_seaworthy` and an HTML report is written
to `htmlcov/`.

> [!NOTE]
> The DynamoDB tests run against [moto](https://github.com/getmoto/moto)'s
> server mode, started in-process on `127.0.0.1`, so the suite needs neither AWS
> credentials nor Docker.

Besides the locked test run, CI runs the suite against the lowest versions the
declared dependency floors admit (`run-test-lowest.yml`), and installs the built
wheel without the lock every night to catch upstream releases that break it
(`run-smoke.yml`).

## Contributing Changes

**With write access to this repository:**

1. Create a feature branch (e.g. `feat/my-change`) directly in the repo
2. Make commits on that branch
3. Open a Pull Request targeting `main`
4. Have the PR reviewed, approved, and merged

**Without write access:**

Fork the repository and follow the same procedure as above.

## Release Process

1. Ensure all changes are committed and the `main` branch is up to date.

2. Create and push a version tag:

   ```bash
   git tag v[X.Y.Z]
   git push origin v[X.Y.Z]
   ```

3. Create a GitHub release from the tag and add release notes. The
   `publish.yml` workflow triggers automatically and uploads to PyPI.

### Testing a release first

To publish to TestPyPI before a real release, trigger the `publish-test.yml`
workflow manually from the **Actions** tab on GitHub (select **Run workflow**).

The package version is derived automatically from the git tag by
[uv-dynamic-versioning](https://github.com/ninoseki/uv-dynamic-versioning).

## Building Packages Locally

```bash
uv build
ls dist/
```

This produces both a wheel (`.whl`) and a source distribution (`.tar.gz`).

## Dependency Management

Dependencies are pinned in `uv.lock` for reproducible installs. After adding or
changing dependencies in `pyproject.toml`:

```bash
uv lock        # update the lockfile
uv sync        # sync your environment to the new lockfile
```

> [!IMPORTANT]
> Always commit both `pyproject.toml` and `uv.lock` together.
