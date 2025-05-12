#!/bin/bash

# Configuration file for DNS Poisoning Monitor
# Customize these settings to match your monitoring requirements

# Domains to monitor
# Add all relevant domains/subdomains to capture the full scope of the attack
DOMAINS=(
  "digitalpacific.com.au"
  "fedora.mirror.digitalpacific.com.au"
  "ubuntu.mirror.digitalpacific.com.au"
)

# Specific mirror domains - will be used for content comparison and detailed testing
MIRROR_DOMAINS=(
  "fedora.mirror.digitalpacific.com.au"
  "ubuntu.mirror.digitalpacific.com.au"
  "debian.mirror.digitalpacific.com.au"
  "centos.mirror.digitalpacific.com.au"
  "mirror.digitalpacific.com.au"
)

# DNS query types to monitor
QUERY_TYPES=(
  "NS"  # Nameserver records (primary target of poisoning)
  "A"   # IPv4 address records
  "SOA" # Start of Authority records (useful for TTL patterns)
)

# DNS servers to monitor
# Include both poisoned Superloop servers and control servers
DNS_SERVERS=(
  "119.40.106.35"  # Superloop DNS 1 (poisoned)
  "119.40.106.36"  # Superloop DNS 2 (poisoned)
  "1.1.1.1"        # Cloudflare (control server)
  "162.159.25.173" # Cloudflare nameserver (authoritative for Digital Pacific)
)

# Network and query settings
DIG_TIMEOUT=5               # Seconds to wait for each DNS response
DIG_RETRIES=3               # Number of retries for failed queries
HTTP_TIMEOUT=10             # Seconds to wait for HTTP/HTTPS responses
HTTPS_TIMEOUT=15            # Seconds to wait for SSL certificate retrieval
SKIP_DEPENDENCY_CHECK=false # Skip checking for required tools

# Content and certificate verification
CHECK_HTTP_CONTENT=true # Whether to fetch and compare HTTP/HTTPS content

# Alert settings
SEND_EMAIL=false         # Set to true to enable email alerts
EMAIL_RECIPIENT=""       # Email address to receive alerts
DETAILED_MONITORING=true # Enable detailed monitoring when poisoning is detected

# Mirror HTTP security settings
CHECK_MIRROR_REDIRECTS=true                                      # Whether to check mirrors for HTTP to HTTPS redirects
MIRRORS_URL="https://mirror.digitalpacific.com.au/?page=mirrors" # URL to fetch mirror list

# Reporting settings
GENERATE_DAILY_SUMMARY=true # Generate a daily analysis summary
