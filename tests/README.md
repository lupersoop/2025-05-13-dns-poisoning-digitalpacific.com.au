# DNS Monitoring System Tests

This directory contains the test suite for the DNS monitoring system. Tests are written using the [Bats](https://github.com/bats-core/bats-core) framework.

## Directory Structure

- `*.bats` - Test files for different components of the system
- `test_helper.bash` - Helper functions and setup for tests
- `run_tests.sh` - Script to run all tests
- `debug_report.sh` - Script to generate debug reports for troubleshooting
- `/fixtures` - Contains test fixtures (sample data for tests)
  - `/certs` - Sample SSL certificate files
  - `/dig` - Sample dig command outputs
  - `/html` - Sample HTML content
  - `/http` - Sample HTTP responses
  - `/outputs` - Store generated output files for inspection
- `/temp` - Temporary files created during test runs
  - `/test_data` - Test data directory structure that mirrors the main data directory

## Running Tests

To run all tests:

```bash
./run_tests.sh
```

To run a specific test file:

```bash
bats dns_analysis.bats
```

## Test Coverage

The test suite covers:

- DNS analysis and poisoning detection
- HTTP/HTTPS security checks
- Certificate validation
- Mirror discovery and redirect checks
- Integration testing of the full system

## Debugging

For detailed test output:

```bash
bats --print-output-on-failure <test_file>
```

To generate a debug report for troubleshooting:

```bash
./debug_report.sh
```