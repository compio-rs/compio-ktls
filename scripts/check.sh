#!/bin/bash
set -e

echo "Running cargo fmt..."
cargo +nightly fmt --all -- --check

echo ""
echo "Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo ""
echo "Running tests..."
cargo test --all-features

echo ""
echo "Building documentation..."
cargo doc --all-features --no-deps

echo ""
echo "✓ All checks passed!"
