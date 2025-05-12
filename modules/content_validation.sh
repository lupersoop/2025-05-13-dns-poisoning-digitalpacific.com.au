#!/bin/bash
#
# content_validation.sh - HTTP content validation functions
# Part of the Digital Pacific DNS Poisoning investigation (May 2025)
#
# This module provides functions for retrieving and analyzing HTTP/HTTPS content
#

# Ensure the script is being sourced, not executed directly
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  echo "Error: This script should be sourced, not executed directly."
  echo "Usage: source content_validation.sh"
  exit 1
fi

# Maintain a list of checked domain/IP/scheme combinations to avoid duplicate alerts
declare -A checked_content_combos

# Function to capture and compare HTTP content
# Parameters:
#   $1 - Domain name
#   $2 - IP address
#   $3 - Scheme (http or https)
# Returns:
#   0 - Content captured successfully
#   1 - Failed to capture content
capture_http_content() {
  local domain="$1"
  local ip="$2"
  local scheme="$3" # http or https
  local content_file="${CONTENT_DIR}/${domain//\./_}_${scheme}_at_${ip//\./_}.html"
  local headers_file="${CONTENT_DIR}/${domain//\./_}_${scheme}_at_${ip//\./_}_headers.txt"

  # Check if we've already processed this combination
  local check_key="${domain}_${ip}_${scheme}"
  if [[ "${checked_content_combos[$check_key]}" == "checked" ]]; then
    # Already checked this combination, skip
    echo "  Skipping already checked $scheme content for $domain at IP $ip"
    return 0
  fi

  # Mark as checked to avoid duplicate processing
  checked_content_combos["$check_key"]="checked"

  echo "Capturing $scheme content for $domain at IP $ip..."

  # Create custom curl options based on scheme
  local curl_opts="-s -L -m $HTTP_TIMEOUT"
  if [[ "$scheme" == "https" ]]; then
    # For HTTPS, we need to ignore certificate errors for poisoned servers
    curl_opts="$curl_opts -k"
  fi

  # Add Host header to force the server to respond for this domain
  curl $curl_opts -D "$headers_file" -H "Host: $domain" "$scheme://$ip/" > "$content_file" 2>/dev/null
  local curl_status=$?

  if [[ $curl_status -ne 0 || ! -s "$content_file" ]]; then
    echo "  Failed to retrieve $scheme content for $domain at $ip (curl status: $curl_status)"
    echo "ERROR: Content retrieval failed" > "$content_file"
    return 1
  fi

  # Calculate content hash for later comparison
  md5sum "$content_file" | awk '{print $1}' > "${content_file}.md5"

  # Analyze content for suspicious indicators
  analyze_content "$content_file" "$domain" "$ip" "$scheme"

  # Analyze headers for security indicators
  analyze_headers "$headers_file" "$domain" "$ip" "$scheme"

  return 0
}

# Analyze HTTP content for suspicious indicators
# Parameters:
#   $1 - Content file path
#   $2 - Domain name
#   $3 - IP address
#   $4 - Scheme (http or https)
# Returns:
#   0 - No suspicious indicators
#   1 - Suspicious indicators found
analyze_content() {
  local content_file="$1"
  local domain="$2"
  local ip="$3"
  local scheme="$4"
  local suspicious=0
  
  # Check for indicators of malicious or unexpected content
  if grep -i -q "hacked\|trojan\|malware\|virus\|exploit\|backdoor" "$content_file"; then
    write_alert "SUSPICIOUS CONTENT: $domain at $ip via $scheme contains potentially malicious keywords"
    suspicious=1
  fi
  
  # Check for unexpected redirects in JavaScript
  if grep -i -q "window.location\|document.location" "$content_file"; then
    write_alert "POTENTIAL REDIRECT: $domain at $ip via $scheme contains JavaScript redirects"
    suspicious=1
  fi
  
  # Check for hidden iframes which might be injecting malicious content
  if grep -i -q "<iframe.*style=.*hidden\|<iframe.*hidden" "$content_file"; then
    write_alert "HIDDEN IFRAME: $domain at $ip via $scheme contains hidden iframes"
    suspicious=1
  fi
  
  # Check for obfuscated JavaScript (common in exploits)
  if grep -q "eval(" "$content_file" || grep -q "document.write(unescape" "$content_file"; then
    write_alert "OBFUSCATED JS: $domain at $ip via $scheme contains potentially obfuscated JavaScript"
    suspicious=1
  fi
  
  return $suspicious
}

# Analyze HTTP headers for security indicators
# Parameters:
#   $1 - Headers file path
#   $2 - Domain name
#   $3 - IP address
#   $4 - Scheme (http or https)
# Returns:
#   0 - No suspicious indicators
#   1 - Suspicious indicators found
analyze_headers() {
  local headers_file="$1"
  local domain="$2"
  local ip="$3"
  local scheme="$4"
  local suspicious=0
  
  # Check for missing security headers when using HTTPS
  if [[ "$scheme" == "https" ]]; then
    # Check for Strict-Transport-Security header
    if ! grep -i -q "Strict-Transport-Security:" "$headers_file"; then
      write_alert "MISSING SECURITY HEADER: $domain at $ip via $scheme is missing HSTS header"
      suspicious=1
    fi
    
    # Check for X-Content-Type-Options header
    if ! grep -i -q "X-Content-Type-Options:" "$headers_file"; then
      write_alert "MISSING SECURITY HEADER: $domain at $ip via $scheme is missing X-Content-Type-Options header"
      suspicious=1
    fi
  fi
  
  # Check for unusual server headers that might indicate poisoning
  local server_header=$(grep -i "Server:" "$headers_file" | head -1)
  if echo "$server_header" | grep -i -q "nginx" && [[ "$domain" == *"digitalpacific"* ]]; then
    # Digital Pacific typically uses Apache, so nginx might be suspicious
    write_alert "UNUSUAL SERVER: $domain at $ip via $scheme is using nginx (Digital Pacific typically uses Apache)"
    suspicious=1
  fi
  
  # Check for unexpected redirects
  if grep -i -q "Location:" "$headers_file"; then
    local redirect_url=$(grep -i "Location:" "$headers_file" | head -1 | awk '{print $2}' | tr -d '\r')
    
    # If redirecting to a different domain, might be suspicious
    if [[ "$redirect_url" != *"$domain"* ]]; then
      write_alert "SUSPICIOUS REDIRECT: $domain at $ip via $scheme redirects to different domain: $redirect_url"
      suspicious=1
    fi
  fi
  
  return $suspicious
}

# Compare content across IPs for the same domain
# Parameters:
#   $1 - Domain name
#   $2 - Scheme (http or https)
#   $3... - Array of IP addresses
# Returns:
#   0 - All content matches or insufficient data
#   1 - Mismatched content detected
compare_content() {
  local domain="$1"
  local scheme="$2"
  shift 2
  local ips=("$@")
  
  # Need at least 2 IPs to compare
  if [[ ${#ips[@]} -lt 2 ]]; then
    return 0
  fi
  
  echo "Comparing $scheme content for $domain across ${#ips[@]} IPs..."
  
  # Get reference content hash from first IP
  local ref_ip="${ips[0]}"
  local ref_md5_file="${CONTENT_DIR}/${domain//\./_}_${scheme}_at_${ref_ip//\./_}.html.md5"
  
  if [[ ! -f "$ref_md5_file" ]]; then
    echo "  No valid reference content hash for comparison"
    return 0
  fi
  
  local ref_hash=$(cat "$ref_md5_file")
  
  if [[ -z "$ref_hash" ]]; then
    echo "  Empty reference content hash"
    return 0
  fi
  
  local mismatch=0
  
  # Compare with all other IPs
  for ((i=1; i<${#ips[@]}; i++)); do
    local ip="${ips[$i]}"
    local md5_file="${CONTENT_DIR}/${domain//\./_}_${scheme}_at_${ip//\./_}.html.md5"
    
    if [[ -f "$md5_file" ]]; then
      local hash=$(cat "$md5_file")
      
      if [[ -n "$hash" && "$hash" != "$ref_hash" ]]; then
        write_alert "CONTENT MISMATCH: $domain has different $scheme content at ${ref_ip} and ${ip}"
        mismatch=1
      fi
    fi
  done
  
  return $mismatch
}