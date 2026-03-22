# Contributing to compio-ktls

Thank you for your interest in contributing to compio-ktls!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/compio-ktls.git`
3. Create a new branch: `git checkout -b my-feature`

## Development Setup

### Prerequisites

- Linux kernel 6.6 LTS or newer (for running tests)
- kTLS kernel module loaded: `sudo modprobe tls`

Run the environment check script:

```bash
./scripts/check-ktls.sh
```

### Running Tests

```bash
# Run all checks (fmt, clippy, tests, doc)
./scripts/check.sh

# Or run individually
cargo +nightly fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --all-features --no-deps
```

## Making Changes

1. **Code Style**: Follow the project's code style. Run `cargo fmt` before committing.
2. **Tests**: Add tests for new functionality. Ensure all tests pass.
3. **Documentation**: Update documentation for public APIs.
4. **Commit Messages**: Write clear, concise commit messages.

## Pull Request Process

1. Ensure all tests pass locally
2. Update documentation if needed
3. Create a pull request with a clear description of changes
4. Address any feedback from reviewers

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help create a welcoming environment for all contributors

## License

By contributing, you agree that your contributions will be licensed under the same licenses as the project (Apache-2.0 OR MulanPSL-2.0).

