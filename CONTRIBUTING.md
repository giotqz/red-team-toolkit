# Contributing to Red Team Toolkit

Thank you for your interest in contributing to Red Team Toolkit! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful and professional. This tool is for authorized security testing only. Users are responsible for legal compliance.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/red-team-toolkit.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Install development dependencies: `pip install -r requirements.txt`

## Development Guidelines

### Code Style

- Follow PEP 8 style guidelines
- Use type hints in function definitions
- Write descriptive docstrings for all functions and classes
- Keep functions focused and modular

### Testing

- Write tests for new features
- Run tests before submitting PR: `pytest tests/`
- Aim for >80% code coverage

### Documentation

- Update README.md if adding new features
- Add docstrings to all new functions
- Include usage examples for major features

## Submitting Changes

1. Commit your changes with clear messages: `git commit -m "Add feature: description"`
2. Push to your fork: `git push origin feature/your-feature-name`
3. Submit a pull request to the main repository
4. Wait for review and address feedback

## Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Include examples or test cases if applicable
- Ensure all tests pass

## Areas for Contribution

- New vulnerability checks
- Additional service modules
- Improved reporting formats
- Documentation
- Bug fixes
- Performance improvements

## Reporting Security Issues

⚠️ **Important**: If you discover a security vulnerability in this tool or the testing framework, please **do not** open a public GitHub issue.

Instead:
1. Email security details privately
2. Allow time for patches
3. Coordinate responsible disclosure

## License

By contributing, you agree your contributions are licensed under the MIT License.

## Questions?

Feel free to open an issue for questions about contributing.

Thank you for helping improve Red Team Toolkit!
