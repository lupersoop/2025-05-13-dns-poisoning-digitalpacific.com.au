#!/bin/bash
#
# certificate_validation.sh - SSL certificate validation functions
# Part of the Digital Pacific DNS Poisoning investigation (May 2025)
#
# This module provides functions for retrieving and analyzing SSL certificates
#

# Ensure the script is being sourced, not executed directly
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  echo "Error: This script should be sourced, not executed directly."
  echo "Usage: source certificate_validation.sh"
  exit 1
fi

# Maintain a list of checked domain/IP combinations to avoid duplicate certificate checks
declare -A checked_certs

# Function to capture SSL certificates
# Parameters:
#   $1 - Domain name
#   $2 - IP address
# Returns:
#   0 - Certificate retrieved successfully
#   1 - Failed to retrieve certificate
capture_certificates() {
  local domain="$1"
  local ip="$2"
  local cert_file="${CERT_DIR}/${domain//\./_}_at_${ip//\./_}.pem"
  local cert_info_file="${CERT_DIR}/${domain//\./_}_at_${ip//\./_}_info.txt"

  # Check if we've already processed this combination
  local check_key="${domain}_${ip}"
  if [[ "${checked_certs[$check_key]}" == "checked" ]]; then
    # Already checked this combination, skip
    echo "  Skipping already checked certificate for $domain at IP $ip"
    return 0
  fi

  # Mark as checked to avoid duplicate processing
  checked_certs["$check_key"]="checked"

  echo "Capturing certificate for $domain at IP $ip..."

  # Capture certificate without verification
  timeout $HTTPS_TIMEOUT openssl s_client -connect "$ip:443" -servername "$domain" -showcerts </dev/null 2>/dev/null | \
    sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$cert_file"

  # Extract certificate information if we got a certificate
  if [[ -s "$cert_file" ]]; then
    openssl x509 -in "$cert_file" -text -noout > "$cert_info_file" 2>/dev/null

    # Check for suspicious/poisoning indicators in certificate
    analyze_certificate "$cert_info_file" "$domain" "$ip"
    return 0
  else
    echo "  No valid certificate obtained for $domain at $ip"
    echo "NO CERTIFICATE OBTAINED" > "$cert_file"
    return 1
  fi
}

# Analyze certificate for suspicious indicators
# Parameters:
#   $1 - Certificate info file path
#   $2 - Domain name
#   $3 - IP address
# Returns:
#   0 - No suspicious indicators
#   1 - Suspicious indicators found
analyze_certificate() {
  local cert_info_file="$1"
  local domain="$2"
  local ip="$3"
  local suspicious=0
  
  # Check for suspicious indicators
  if grep -q "has.email" "$cert_info_file"; then
    write_alert "SUSPICIOUS CERTIFICATE: Domain $domain at IP $ip has certificate with has.email in it"
    suspicious=1
  fi
  
  # Check certificate issuer for suspicious patterns
  local issuer=$(grep "Issuer:" "$cert_info_file")
  if echo "$issuer" | grep -qi "free\|fake\|temporary\|invalid"; then
    write_alert "SUSPICIOUS CERTIFICATE ISSUER: Domain $domain at IP $ip has unusual issuer: $issuer"
    suspicious=1
  fi
  
  # Check certificate validity periods
  local valid_from=$(grep "Not Before:" "$cert_info_file" | awk -F': ' '{print $2}')
  local valid_to=$(grep "Not After :" "$cert_info_file" | awk -F': ' '{print $2}')
  
  # Convert dates to timestamp for comparison
  local now=$(date +%s)
  local from_ts=$(date -d "$valid_from" +%s 2>/dev/null)
  local to_ts=$(date -d "$valid_to" +%s 2>/dev/null)
  
  # Check for very short-lived certificates (less than 7 days)
  if [[ -n "$from_ts" && -n "$to_ts" ]]; then
    local validity_days=$(( (to_ts - from_ts) / 86400 ))
    if [[ $validity_days -lt 7 ]]; then
      write_alert "SHORT-LIVED CERTIFICATE: Domain $domain at IP $ip has certificate valid for only $validity_days days"
      suspicious=1
    fi
  fi
  
  # Check for subject/domain mismatch
  local subject=$(grep "Subject:" "$cert_info_file")
  if ! echo "$subject" | grep -iq "$domain"; then
    write_alert "CERTIFICATE DOMAIN MISMATCH: Domain $domain at IP $ip has certificate with subject: $subject"
    suspicious=1
  fi
  
  return $suspicious
}

# Compare certificates across IPs for the same domain
# Parameters:
#   $1 - Domain name
#   $2 - Array of IP addresses
# Returns:
#   0 - All certificates match or insufficient data
#   1 - Mismatched certificates detected
compare_certificates() {
  local domain="$1"
  shift
  local ips=("$@")
  
  # Need at least 2 IPs to compare
  if [[ ${#ips[@]} -lt 2 ]]; then
    return 0
  fi
  
  echo "Comparing certificates for $domain across ${#ips[@]} IPs..."
  
  # Get reference certificate hash from first IP
  local ref_ip="${ips[0]}"
  local ref_cert="${CERT_DIR}/${domain//\./_}_at_${ref_ip//\./_}.pem"
  
  if [[ ! -f "$ref_cert" || ! -s "$ref_cert" ]]; then
    echo "  No valid reference certificate for comparison"
    return 0
  fi
  
  local ref_hash=$(openssl x509 -in "$ref_cert" -noout -fingerprint -sha256 2>/dev/null | awk -F'=' '{print $2}')
  
  if [[ -z "$ref_hash" ]]; then
    echo "  Could not calculate reference certificate hash"
    return 0
  fi
  
  local mismatch=0
  
  # Compare with all other IPs
  for ((i=1; i<${#ips[@]}; i++)); do
    local ip="${ips[$i]}"
    local cert="${CERT_DIR}/${domain//\./_}_at_${ip//\./_}.pem"
    
    if [[ -f "$cert" && -s "$cert" ]]; then
      local hash=$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null | awk -F'=' '{print $2}')
      
      if [[ -n "$hash" && "$hash" != "$ref_hash" ]]; then
        write_alert "CERTIFICATE MISMATCH: $domain has different certificates at ${ref_ip} and ${ip}"
        mismatch=1
      fi
    fi
  done
  
  return $mismatch
}