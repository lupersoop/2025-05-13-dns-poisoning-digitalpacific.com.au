#!/bin/bash
#
# Run all Bats tests for the DNS monitoring system
#

set -e

# Check if bats is installed
if ! command -v bats &> /dev/null; then
    echo "Error: bats is not installed. Please install bats-core to run tests:"
    echo "  https://github.com/bats-core/bats-core#installation"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure test directories exist
mkdir -p "${SCRIPT_DIR}/fixtures" "${SCRIPT_DIR}/outputs" "${SCRIPT_DIR}/temp" "${SCRIPT_DIR}/temp/test_data"

# Clean up any previous test outputs
cleanup() {
  echo "Cleaning up test outputs..."
  rm -rf "${SCRIPT_DIR}/temp/test_data"
  rm -f "${SCRIPT_DIR}/outputs/"*
}

# Run cleanup on script exit
trap cleanup EXIT

# Run all the tests
echo "Running all tests..."
bats *.bats

echo "All tests completed."