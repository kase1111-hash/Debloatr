# Contributing to Debloatr

Thank you for your interest in contributing to Debloatr! This document provides guidelines and instructions for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Windows 10 (1903+) or Windows 11 for full functionality
- Git

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/debloatr/debloatr.git
   cd debloatr
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

4. **Install the package in development mode**
   ```bash
   pip install -e .
   ```

## Development Workflow

### Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting (line length: 100)
- **Ruff** for linting
- **mypy** for type checking

Run all checks before submitting:

```bash
# Format code
black src tests

# Lint
ruff check src tests

# Type check
mypy src
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_models.py

# Run tests with verbose output
pytest -v
```

### Project Structure

```
debloatr/
├── src/                    # Source code
│   ├── core/               # Core infrastructure
│   ├── discovery/          # System scanning modules
│   ├── classification/     # Bloatware classification
│   ├── analysis/           # Risk analysis
│   ├── actions/            # Action handlers
│   └── ui/                 # User interfaces (CLI/GUI)
├── data/                   # Data files
│   ├── signatures/         # Bloatware signatures
│   └── profiles/           # Configuration profiles
├── tests/                  # Test suite
└── docs/                   # Documentation
```

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates. When creating a bug report, include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- System information (Windows version, Python version)
- Relevant logs or error messages

### Suggesting Features

Feature suggestions are welcome! Please include:

- A clear description of the feature
- The problem it solves or use case
- Any implementation ideas you have

### Submitting Changes

1. **Fork the repository** and create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our code style guidelines

3. **Write or update tests** for your changes

4. **Run the test suite** to ensure all tests pass

5. **Commit your changes** with a clear, descriptive message:
   ```bash
   git commit -m "Add feature: description of what you added"
   ```

6. **Push to your fork** and create a Pull Request

### Pull Request Guidelines

- Keep PRs focused on a single feature or fix
- Update documentation if needed
- Add tests for new functionality
- Ensure all CI checks pass
- Reference any related issues

### Commit Message Format

Use clear, descriptive commit messages:

- `Add: new feature or file`
- `Fix: bug fix description`
- `Update: enhancement to existing feature`
- `Refactor: code restructuring`
- `Docs: documentation changes`
- `Test: test additions or fixes`

## Contributing to Signatures

The signature database is critical for accurate bloatware detection. When adding signatures:

1. **Research thoroughly** - Document evidence for the classification
2. **Test on real systems** - Verify the signature matches correctly
3. **Include evidence URLs** - Link to sources supporting the classification
4. **Consider safe actions** - Mark which actions are safe for the component

### Signature Format

```json
{
  "signature_id": "publisher-component-001",
  "publisher": "Publisher Name",
  "component_name": "Component Display Name",
  "component_type": "service|program|task|startup|driver|uwp",
  "match_rules": {
    "name_pattern": "regex pattern",
    "publisher_pattern": "regex pattern",
    "path_pattern": "regex pattern"
  },
  "classification": "BLOAT|AGGRESSIVE|OPTIONAL|ESSENTIAL|CORE",
  "safe_actions": ["disable", "remove", "contain"],
  "evidence_url": "https://example.com/evidence",
  "breakage_notes": "Any known issues from disabling/removing"
}
```

## Design Principles

When contributing, keep these principles in mind:

1. **Determinism** - Prefer signature-based classification over heuristic guessing
2. **Reversibility** - Every action must be undoable; snapshots before changes
3. **Evidence-backed** - Classifications require documented rationale
4. **Human-auditable** - All decisions logged with reasoning visible to user

## Questions?

If you have questions about contributing, feel free to open an issue for discussion.

## License

By contributing to Debloatr, you agree that your contributions will be licensed under the CC0 1.0 Universal license.
