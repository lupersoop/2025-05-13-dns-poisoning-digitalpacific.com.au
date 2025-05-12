# DNS Poisoning Monitoring Modules

This directory contains modular components of the DNS poisoning monitoring system. Each module
provides specific functionality that can be used independently or combined with other modules
for comprehensive monitoring.

## Available Modules

### utils.sh
Common utility functions used across all modules, including:
- Directory structure creation
- Alert handling
- Change detection
- Daily summary generation
- Tool dependency checking

### dns_analysis.sh
Functions for analyzing DNS query responses:
- TTL extraction
- Nameserver extraction
- IP address extraction
- Response time measurement
- Poisoning pattern detection
- Query execution with retries

### certificate_validation.sh
SSL certificate retrieval and analysis:
- Certificate capture from IP addresses
- Certificate content analysis
- Suspicious certificate detection
- Certificate comparison across IPs

### content_validation.sh
HTTP/HTTPS content validation:
- Content retrieval from IP addresses
- Malicious content pattern detection
- HTTP header analysis
- Content comparison across IPs

### http_security.sh
HTTP security checking functions:
- HTTPS redirect checking
- Security header validation
- HSTS enforcement checking
- Mixed content detection
- Domain security validation

### mirror_discovery.sh
Mirror server discovery and analysis:
- Mirror list fetching
- HTTP to HTTPS redirect checking
- Generating mirror security reports

## Usage

Each module can be used independently by sourcing it in your script:

```bash
source /path/to/modules/utils.sh
source /path/to/modules/dns_analysis.sh
# etc.
```

All modules should be sourced, not executed directly. Each module contains appropriate error 
handling to prevent direct execution.

## Function Documentation

Each module file contains detailed documentation for every function, including:
- Function purpose
- Required parameters
- Return values
- Error handling

## Examples

### Basic DNS Query Analysis

```bash
#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

source "${MODULES_DIR}/utils.sh"
source "${MODULES_DIR}/dns_analysis.sh"

# Create data directories
create_data_directories

# Perform a DNS query
perform_dns_query "example.com" "A" "8.8.8.8" "output.txt"

# Extract information
dig_output=$(cat "output.txt")
ttl=$(extract_ttl "$dig_output")
nameservers=$(extract_nameservers "$dig_output" "A")
ip_addresses=$(extract_ips "$dig_output" "A")

echo "TTL: $ttl"
echo "Nameservers: $nameservers"
echo "IP Addresses: $ip_addresses"
```

### HTTP Security Check

```bash
#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

source "${MODULES_DIR}/http_security.sh"

# Check if a site redirects to HTTPS
redirect_info=$(check_https_redirect "http://example.com")
echo "Redirect info: $redirect_info"

# Check for security headers
missing_headers=$(check_security_headers "https://example.com")
echo "Missing security headers: $missing_headers"
```

## Module Dependencies

- `utils.sh` - No dependencies
- `dns_analysis.sh` - Depends on utils.sh
- `certificate_validation.sh` - Depends on utils.sh
- `content_validation.sh` - Depends on utils.sh
- `http_security.sh` - No dependencies
- `mirror_discovery.sh` - Depends on http_security.sh

Always load dependent modules before loading modules that depend on them.