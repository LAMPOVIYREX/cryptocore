#!/bin/bash

echo "=== Running Simple Tests Only ==="
echo "This skips problematic integration tests"

# Go to project root
cd "$(dirname "$0")/../.."

# Run unit tests
echo ""
echo "Running unit tests..."
make test

echo ""
echo "=== Unit tests completed ==="
echo "To run integration tests separately, use:"
echo "  ./tests/scripts/simple_test.sh"