#!/bin/bash
#
# Generate a debug report for the DNS monitoring system tests
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Create debug report directory
DEBUG_DIR="$SCRIPT_DIR/debug_report_$(date +"%Y%m%d_%H%M%S")"
mkdir -p "$DEBUG_DIR"

echo "Generating debug report in $DEBUG_DIR..."

# Run tests with detailed output
echo "Running tests with detailed output..."
bats --verbose --print-output-on-failure *.bats > "$DEBUG_DIR/test_output.log" 2>&1 || true

# Gather system information
echo "Gathering system information..."
{
  echo "=== System Information ==="
  echo "Date: $(date)"
  echo "Hostname: $(hostname)"
  echo "OS: $(uname -a)"
  echo ""
  
  echo "=== Software Versions ==="
  echo "Bash version: $(bash --version | head -1)"
  echo "Bats version: $(bats --version 2>&1 | head -1)"
  echo "Dig version: $(dig -v 2>&1 | head -1)"
  echo "Curl version: $(curl --version | head -1)"
  echo "OpenSSL version: $(openssl version)"
  echo "Whois version: $(whois --version 2>&1 | head -1 || echo "whois version not available")"
  echo ""
  
  echo "=== Environment Variables ==="
  env | sort
  echo ""
  
  echo "=== Directory Structure ==="
  find "$SCRIPT_DIR" -type d | sort
  echo ""
  
  echo "=== Files ==="
  find "$SCRIPT_DIR" -type f -name "*.sh" -o -name "*.bats" -o -name "*.bash" | sort
  echo ""
  
  echo "=== Test Helper ==="
  cat "$SCRIPT_DIR/test_helper.bash"
  echo ""
  
} > "$DEBUG_DIR/system_info.txt"

# Create a zip archive with all test files
echo "Creating test files archive..."
mkdir -p "$DEBUG_DIR/test_files"
cp -r "$SCRIPT_DIR"/*.bats "$DEBUG_DIR/test_files/"
cp -r "$SCRIPT_DIR"/*.sh "$DEBUG_DIR/test_files/"
cp -r "$SCRIPT_DIR"/*.bash "$DEBUG_DIR/test_files/"
cp -r "$SCRIPT_DIR/../modules" "$DEBUG_DIR/test_files/"
cp "$SCRIPT_DIR/../dns_monitor.sh" "$DEBUG_DIR/test_files/"
cp "$SCRIPT_DIR/../config.sh" "$DEBUG_DIR/test_files/" 2>/dev/null || echo "config.sh not found"

# If there are any test fixtures, copy them too
if [ -d "$SCRIPT_DIR/fixtures" ]; then
  mkdir -p "$DEBUG_DIR/test_files/fixtures"
  cp -r "$SCRIPT_DIR/fixtures"/* "$DEBUG_DIR/test_files/fixtures/" 2>/dev/null || echo "No fixture files found"
fi

# Compress the debug report
cd "$(dirname "$DEBUG_DIR")"
tar -czf "$(basename "$DEBUG_DIR").tar.gz" "$(basename "$DEBUG_DIR")"
echo "Debug report compressed to $(dirname "$DEBUG_DIR")/$(basename "$DEBUG_DIR").tar.gz"

echo "Debug report generation complete."
echo "Please attach $(dirname "$DEBUG_DIR")/$(basename "$DEBUG_DIR").tar.gz when reporting issues."