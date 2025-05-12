#!/bin/bash
#
# http_security.sh - HTTP security validation functions
# Part of the Digital Pacific DNS Poisoning investigation (May 2025)
#
# This module provides functions for checking HTTP redirects and security headers
#

# Ensure the script is being sourced, not executed directly
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  echo "Error: This script should be sourced, not executed directly."
  echo "Usage: source http_security.sh"
  exit 1
fi

# Check if a URL redirects to HTTPS
# Parameters:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional, defaults to 10)
# Returns: Array with [status_code, redirects_to_https, redirect_url]
check_https_redirect() {
  local url="$1"
  local timeout="${2:-10}"
  
  # Get HTTP status code and redirect URL
  local result=$(curl -s -m "$timeout" -o /dev/null -w "%{http_code},%{redirect_url}" "$url" 2>/dev/null)
  
  local status_code=$(echo "$result" | cut -d',' -f1)
  local redirect_url=$(echo "$result" | cut -d',' -f2-)
  
  # Check if redirect URL starts with https://
  local redirects_to_https="No"
  if [[ -n "$redirect_url" && "$redirect_url" == https://* ]]; then
    redirects_to_https="Yes"
  fi
  
  echo "${status_code},${redirects_to_https},${redirect_url}"
}

# Check for secure HTTP headers
# Parameters:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional, defaults to 10)
# Returns: Comma-separated string of missing security headers
check_security_headers() {
  local url="$1"
  local timeout="${2:-10}"
  local missing_headers=""
  
  # Get headers
  local headers=$(curl -s -m "$timeout" -I "$url" 2>/dev/null)
  
  # Check for important security headers
  if ! echo "$headers" | grep -qi "Strict-Transport-Security"; then
    missing_headers="HSTS"
  fi
  
  if ! echo "$headers" | grep -qi "X-Content-Type-Options"; then
    missing_headers="${missing_headers:+$missing_headers,}X-Content-Type-Options"
  fi
  
  if ! echo "$headers" | grep -qi "X-Frame-Options"; then
    missing_headers="${missing_headers:+$missing_headers,}X-Frame-Options"
  fi
  
  if ! echo "$headers" | grep -qi "Content-Security-Policy"; then
    missing_headers="${missing_headers:+$missing_headers,}CSP"
  fi
  
  if ! echo "$headers" | grep -qi "X-XSS-Protection"; then
    missing_headers="${missing_headers:+$missing_headers,}X-XSS-Protection"
  fi
  
  # Return the comma-separated list or "None" if all headers are present
  if [[ -z "$missing_headers" ]]; then
    echo "None"
  else
    echo "$missing_headers"
  fi
}

# Check if a site enforces HTTPS through HSTS
# Parameters:
#   $1 - URL to check (must be HTTPS)
#   $2 - Timeout in seconds (optional, defaults to 10)
# Returns:
#   0 - HSTS is enabled
#   1 - HSTS is not enabled
check_hsts() {
  local url="$1"
  local timeout="${2:-10}"
  
  # Make sure URL is HTTPS
  if [[ "$url" != https://* ]]; then
    url="https://${url#http://}"
  fi
  
  # Get headers
  local headers=$(curl -s -m "$timeout" -I "$url" 2>/dev/null)
  
  # Check for HSTS header
  if echo "$headers" | grep -qi "Strict-Transport-Security"; then
    return 0
  else
    return 1
  fi
}

# Check for mixed content on a page
# Parameters:
#   $1 - URL to check (must be HTTPS)
#   $2 - Timeout in seconds (optional, defaults to 10)
# Returns:
#   0 - No mixed content found
#   1 - Mixed content found
check_mixed_content() {
  local url="$1"
  local timeout="${2:-10}"
  local temp_file=$(mktemp)
  
  # Make sure URL is HTTPS
  if [[ "$url" != https://* ]]; then
    url="https://${url#http://}"
  fi
  
  # Get page content
  curl -s -m "$timeout" "$url" > "$temp_file" 2>/dev/null
  
  # Look for HTTP resources in the page
  if grep -qi 'src="http://' "$temp_file" || grep -qi "src='http://" "$temp_file" || 
     grep -qi 'href="http://' "$temp_file" || grep -qi "href='http://" "$temp_file"; then
    rm "$temp_file"
    return 1
  else
    rm "$temp_file"
    return 0
  fi
}

# Validate HTTP security for a list of domains
# Parameters:
#   $1 - Array of domains to check
#   $2 - Timeout in seconds (optional, defaults to 10)
#   $3 - Output file for results (optional)
# Returns: Newline-separated security check results
validate_domains_security() {
  local domains=("$1")
  local timeout="${2:-10}"
  local output_file="$3"
  
  if [[ -n "$output_file" ]]; then
    echo "Domain,HTTPS Redirect,Status Code,Redirect URL,Missing Security Headers,HSTS Enabled,Mixed Content" > "$output_file"
  fi
  
  local results=""
  
  for domain in "${domains[@]}"; do
    echo "Checking security for $domain..." >&2
    
    # Check HTTP to HTTPS redirect
    local redirect_check=$(check_https_redirect "http://$domain" "$timeout")
    local status_code=$(echo "$redirect_check" | cut -d',' -f1)
    local redirects_to_https=$(echo "$redirect_check" | cut -d',' -f2)
    local redirect_url=$(echo "$redirect_check" | cut -d',' -f3-)
    
    # Check security headers (only if accessible)
    local missing_headers="N/A"
    if [[ $status_code -ge 200 && $status_code -lt 300 ]] || [[ $status_code -ge 300 && $status_code -lt 400 && -n "$redirect_url" ]]; then
      # For 3xx redirects, check the destination URL
      local check_url="$domain"
      if [[ $status_code -ge 300 && $status_code -lt 400 && -n "$redirect_url" ]]; then
        check_url="$redirect_url"
      fi
      
      # Make sure it's https:// for header checks
      if [[ "$check_url" != https://* ]]; then
        check_url="https://${check_url#http://}"
      fi
      
      missing_headers=$(check_security_headers "$check_url" "$timeout")
    fi
    
    # Check HSTS (only if HTTPS is available)
    local hsts_enabled="N/A"
    if [[ "$redirects_to_https" == "Yes" || "$domain" == https://* ]]; then
      if check_hsts "${redirect_url:-$domain}" "$timeout"; then
        hsts_enabled="Yes"
      else
        hsts_enabled="No"
      fi
    fi
    
    # Check for mixed content (only if HTTPS is available)
    local mixed_content="N/A"
    if [[ "$redirects_to_https" == "Yes" || "$domain" == https://* ]]; then
      if check_mixed_content "${redirect_url:-$domain}" "$timeout"; then
        mixed_content="No"
      else
        mixed_content="Yes"
      fi
    fi
    
    # Format result line
    local result="$domain,$redirects_to_https,$status_code,$redirect_url,$missing_headers,$hsts_enabled,$mixed_content"
    results+="$result"$'\n'
    
    # Write to output file if provided
    if [[ -n "$output_file" ]]; then
      echo "$result" >> "$output_file"
    fi
  done
  
  echo "$results"
}