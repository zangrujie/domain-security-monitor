# Contributing to Domain Security Monitor

Thank you for your interest in contributing to Domain Security Monitor! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [How Can I Contribute?](#how-can-i-contribute)
3. [Development Environment Setup](#development-environment-setup)
4. [Code Style Guidelines](#code-style-guidelines)
5. [Testing](#testing)
6. [Pull Request Process](#pull-request-process)
7. [Issue Reporting](#issue-reporting)
8. [Feature Requests](#feature-requests)
9. [Documentation](#documentation)
10. [Community](#community)

## Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for all contributors. By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Use welcoming and inclusive language
- Be collaborative
- Be constructive
- Focus on what's best for the community
- Show empathy towards other community members

## How Can I Contribute?

### Reporting Bugs
- Check if the bug has already been reported in the Issues section
- Use the bug report template when creating a new issue
- Include detailed steps to reproduce the issue
- Include system information (OS, Python/Go versions, etc.)
- Include relevant logs or error messages

### Suggesting Enhancements
- Check if the enhancement has already been suggested
- Use the feature request template
- Clearly describe the enhancement and its benefits
- Consider providing mockups or examples if applicable

### Code Contributions
- Fork the repository
- Create a feature branch
- Make your changes following the code style guidelines
- Add tests for new functionality
- Update documentation as needed
- Submit a pull request

### Documentation
- Fix typos or grammatical errors
- Improve clarity of existing documentation
- Add examples or tutorials
- Translate documentation to other languages

### Testing
- Write new tests for existing features
- Improve test coverage
- Report failing tests

## Development Environment Setup

### Prerequisites
- Python 3.8+
- Go 1.19+
- PostgreSQL 12+
- Git

### Steps

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/domain-security-monitor.git
   cd domain-security-monitor
   ```

2. **Set up Python Environment**
   ```bash
   python -m venv .venv
   
   # Windows
   .venv\Scripts\activate
   
   # Linux/Mac
   source .venv/bin/activate
   
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

3. **Set up Go Environment**
   ```bash
   go mod download
   ```

4. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Set up Database**
   ```bash
   python init_database_fixed.py
   ```

6. **Install Development Tools**
   ```bash
   pre-commit install
   ```

### Development Dependencies

Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

Development dependencies include:
- `pytest` - Testing framework
- `black` - Code formatting
- `flake8` - Code linting
- `mypy` - Type checking
- `pre-commit` - Git hooks

## Code Style Guidelines

### Python Code Style

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with some modifications:

- **Line length**: 88 characters (Black default)
- **Imports**: Grouped and ordered as follows:
  1. Standard library imports
  2. Third-party imports
  3. Local application imports
- **Docstrings**: Use Google style docstrings

#### Formatting
We use [Black](https://github.com/psf/black) for automatic code formatting:

```bash
black modules/ tests/
```

#### Linting
We use [flake8](https://flake8.pycqa.org/) for linting:

```bash
flake8 modules/ tests/
```

#### Type Checking
We use [mypy](https://mypy.readthedocs.io/) for static type checking:

```bash
mypy modules/
```

### Go Code Style

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting:
  ```bash
  gofmt -w main.go xdig.go
  ```

### Naming Conventions

- **Python**: Use `snake_case` for variables and functions, `PascalCase` for classes
- **Go**: Use `camelCase` for variables and functions, `PascalCase` for exported identifiers
- **Database**: Use `snake_case` for table and column names
- **HTML/CSS**: Use `kebab-case` for class names

### Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat(scanner): add support for IPv6 DNS queries

- Implement IPv6 DNS query functionality
- Add tests for IPv6 queries
- Update documentation

Closes #123
```

## Testing

### Running Tests

#### Python Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=modules tests/

# Run specific test
pytest tests/test_scanner.py::TestScanner::test_dns_scan
```

#### Go Tests
```bash
# Run Go tests
go test ./...

# Run with coverage
go test -cover ./...
```

### Writing Tests

#### Python Tests
- Use `pytest` framework
- Place tests in `tests/` directory
- Name test files as `test_*.py`
- Name test functions as `test_*`
- Use fixtures for common setup

Example:
```python
def test_dns_scan():
    """Test DNS scanning functionality."""
    scanner = DNSScanner()
    result = scanner.scan("example.com")
    assert result["status"] == "active"
```

#### Go Tests
- Use Go's built-in testing package
- Name test files as `*_test.go`
- Name test functions as `Test*`

Example:
```go
func TestDomainGeneration(t *testing.T) {
    variants := GenerateVariants("example.com")
    if len(variants) == 0 {
        t.Error("Expected domain variants, got none")
    }
}
```

### Test Coverage Goals
- Aim for at least 80% test coverage
- Critical functionality should have 90%+ coverage
- New features should include tests

## Pull Request Process

1. **Fork the Repository**
   - Click the "Fork" button on GitHub
   - Clone your fork locally

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Your Changes**
   - Follow code style guidelines
   - Add tests for new functionality
   - Update documentation

4. **Run Tests**
   ```bash
   pytest
   go test ./...
   ```

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "feat(scanner): add amazing feature"
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Create Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your feature branch
   - Fill in the PR template
   - Wait for review

### Pull Request Requirements
- All tests must pass
- Code must follow style guidelines
- New features must include tests
- Documentation must be updated
- Must not break existing functionality

### Review Process
- At least one maintainer must approve
- All CI checks must pass
- Address review comments promptly
- Keep PRs focused and small when possible

## Issue Reporting

### Bug Reports
Use the bug report template when creating issues:

```markdown
## Description
Brief description of the bug

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Windows 11, Ubuntu 22.04]
- Python Version: [e.g., 3.9.7]
- Go Version: [e.g., 1.19.3]
- PostgreSQL Version: [e.g., 14.5]

## Additional Context
Screenshots, logs, etc.
```

### Security Issues
For security vulnerabilities, please DO NOT open a public issue. Instead, email `security@example.com` with details.

## Feature Requests

Use the feature request template:

```markdown
## Problem Statement
Describe the problem this feature would solve

## Proposed Solution
Describe your proposed solution

## Alternatives Considered
Describe alternative solutions you've considered

## Additional Context
Any other context about the feature request
```

## Documentation

### Documentation Structure
- `README.md` - Main project documentation
- `USAGE_GUIDE.md` - Detailed usage instructions
- `CONTRIBUTING.md` - This file
- `CODE_OF_CONDUCT.md` - Community guidelines
- Docstrings in code

### Updating Documentation
- Keep documentation up-to-date with code changes
- Use clear, concise language
- Include examples when helpful
- Use Markdown formatting

## Community

### Communication Channels
- GitHub Issues for bug reports and feature requests
- GitHub Discussions for questions and discussions
- Email for security issues

### Recognition
Contributors will be:
- Listed in CONTRIBUTORS.md
- Acknowledged in release notes
- Given credit in relevant documentation

### Getting Help
- Check the documentation first
- Search existing issues and discussions
- Ask questions in GitHub Discussions

## Project Structure

```
domain-security-monitor/
├── modules/                    # Python modules
├── static/                    # Web static files
├── templates/                # Web templates
├── dis_character/            # Character similarity data
├── tests/                    # Test files (to be created)
├── docs/                    # Documentation (to be created)
├── web_app.py              # Flask application
├── main.go                 # Go domain generator
├── xdig.go                 # Go DNS scanner
└── requirements.txt        # Python dependencies
```

## Release Process

1. **Version Bumping**
   - Update version in relevant files
   - Follow semantic versioning

2. **Release Notes**
   - Document new features
   - List bug fixes
   - Acknowledge contributors

3. **Tagging**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

4. **Distribution**
   - Create GitHub release
   - Update documentation
   - Announce to community

## License

By contributing, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

---

Thank you for contributing to Domain Security Monitor! 🎉