#!/bin/bash
#
# utils.sh - Shared utility functions for DNS monitoring system
# Part of the Digital Pacific DNS Poisoning investigation (May 2025)
#
# This module provides common utility functions used across the monitoring system
#

# Ensure the script is being sourced, not executed directly
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  echo "Error: This script should be sourced, not executed directly."
  echo "Usage: source utils.sh"
  exit 1
fi

# Write an alert to the log file and optionally send an email
# Parameters:
#   $1 - Alert text
write_alert() {
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  local alert_text="$1"

  # Make sure ALERTS_LOG is defined
  if [[ -z "$ALERTS_LOG" ]]; then
    echo "Warning: ALERTS_LOG is not defined. Creating default log file."
    ALERTS_LOG="./alerts.log"
  fi

  # Ensure the directory for the log file exists
  local log_dir=$(dirname "$ALERTS_LOG")
  mkdir -p "$log_dir"

  echo "[${timestamp}] ${alert_text}" >> "$ALERTS_LOG"

  # Also output to console
  echo "[ALERT] ${alert_text}"

  if [[ "$SEND_EMAIL" == "true" && -n "$EMAIL_RECIPIENT" ]]; then
    echo "${alert_text}" | mail -s "DNS Poisoning Alert: ${timestamp}" "$EMAIL_RECIPIENT"
  fi
}

# Create required directory structure for data storage
# Creates various subdirectories for organizing monitoring data
# Parameters: none
# Sets global directory variables
create_data_directories() {
  # Create data directory structure
  DATE_STR=$(date +"%Y-%m-%d")
  TIME_STR=$(date +"%H-%M-%S")

  # Use test data directory if in test mode
  if [[ "$TEST_MODE" == "true" && -n "$TEST_DATA_DIR" ]]; then
    DATA_DIR="${TEST_DATA_DIR}/${DATE_STR}"
  else
    DATA_DIR="${SCRIPT_DIR}/data/${DATE_STR}"
  fi

  RAW_DIR="${DATA_DIR}/raw/${TIME_STR}"
  CERT_DIR="${DATA_DIR}/certificates"
  CONTENT_DIR="${DATA_DIR}/content"
  WHOIS_DIR="${DATA_DIR}/whois"
  SYSTEM_DIR="${DATA_DIR}/system"
  HTTPS_DIR="${DATA_DIR}/https"

  # Create all necessary directories
  HASHES_DIR="${DATA_DIR}/hashes"
  mkdir -p "${RAW_DIR}" "${CERT_DIR}" "${CONTENT_DIR}" "${WHOIS_DIR}" "${SYSTEM_DIR}" "${HTTPS_DIR}" "${HASHES_DIR}"

  # Summary files
  SUMMARY_CSV="${DATA_DIR}/summary.csv"
  ALERTS_LOG="${DATA_DIR}/alerts.log"
  
  # Create summary header if it doesn't exist
  if [[ ! -f "$SUMMARY_CSV" ]]; then
    echo "timestamp,domain,query_type,dns_server,ttl,nameservers,ip_addresses,response_time_ms,has_changed" > "$SUMMARY_CSV"
  fi
  
  # Export directory variables
  export DATE_STR TIME_STR DATA_DIR RAW_DIR CERT_DIR CONTENT_DIR WHOIS_DIR SYSTEM_DIR HASHES_DIR
  export SUMMARY_CSV ALERTS_LOG
}

# Check if required tools are installed
# Parameters: none
# Returns: An array of missing tools
check_required_tools() {
  local missing_tools=()

  # Define tool importance and alternatives
  declare -A tool_messages
  tool_messages["dig"]="Missing 'dig' will severely limit DNS analysis capabilities. Install using 'apt-get install dnsutils' on Debian/Ubuntu."
  tool_messages["curl"]="Missing 'curl' will prevent HTTP tests and mirror analysis. Install using 'apt-get install curl' on Debian/Ubuntu."
  tool_messages["host"]="Missing 'host' will limit DNS resolution capabilities. Install using 'apt-get install dnsutils' on Debian/Ubuntu."
  tool_messages["md5sum"]="Missing 'md5sum' will affect file verification. It's typically included in coreutils."
  tool_messages["openssl"]="Missing 'openssl' will prevent certificate validation. Install using 'apt-get install openssl' on Debian/Ubuntu."
  tool_messages["whois"]="Missing 'whois' will prevent collecting domain/IP ownership data. Install using 'apt-get install whois' on Debian/Ubuntu."
  tool_messages["jq"]="Missing 'jq' limits JSON processing. Install using 'apt-get install jq' on Debian/Ubuntu."

  # Check each required tool
  for tool in dig curl host md5sum openssl whois jq; do
    if ! command -v $tool &> /dev/null && [[ "$SKIP_DEPENDENCY_CHECK" != "true" ]]; then
      echo "Warning: $tool is not installed. ${tool_messages[$tool]}"
      missing_tools+=("$tool")

      # For whois, which we detect is often missing, provide alternative
      if [[ "$tool" == "whois" ]]; then
        echo "Alternative: The script will use DNS lookups instead of WHOIS when 'whois' is not available."
      fi
    fi
  done

  # Output the array of missing tools
  echo "${missing_tools[@]}"
}

# Check if response has changed from previous query
# Parameters:
#   $1 - Domain name
#   $2 - Query type (A, NS, etc.)
#   $3 - DNS server
#   $4 - Current response hash
# Returns:
#   0 - No change or first run
#   1 - Change detected
check_for_changes() {
  local domain="$1"
  local query_type="$2"
  local dns_server="$3"
  local current_hash="$4"
  
  # Check previous query results
  local prev_results="${HASHES_DIR}/previous_${domain}_${query_type}_${dns_server//\./_}.hash"

  if [[ -f "$prev_results" ]]; then
    local prev_hash=$(cat "$prev_results")

    if [[ "$prev_hash" != "$current_hash" ]]; then
      write_alert "CHANGE DETECTED: $domain $query_type records from $dns_server have changed"
      echo "1" # Changed
    else
      echo "0" # Unchanged
    fi
  else
    echo "0" # First run, no change
  fi

  # Save current hash for next comparison
  echo "$current_hash" > "${HASHES_DIR}/previous_${domain}_${query_type}_${dns_server//\./_}.hash"
}

# Create daily monitoring summary
# Parameters: none
# Returns: none
generate_daily_summary() {
  if [[ "$GENERATE_DAILY_SUMMARY" == "true" && ! -f "${DATA_DIR}/daily_summary.txt" && ! -f "${DATA_DIR}/daily_summary.md" ]]; then
    # Count number of poisoned responses
    poisoned_count=$(grep -c "has.email" "$SUMMARY_CSV")
    total_queries=$(grep -c "^2" "$SUMMARY_CSV") # Count non-header lines
    
    # Get unique TTLs for poisoned NS records
    unique_ttls=$(grep "has.email" "$SUMMARY_CSV" | cut -d',' -f5 | sort | uniq)
    
    # Calculate TTL decreases to estimate next refresh
    previous_day="${SCRIPT_DIR}/data/$(date -d "yesterday" +"%Y-%m-%d")/summary.csv"
    ttl_decreases=""
    
    if [[ -f "$previous_day" ]]; then
      for server in "${DNS_SERVERS[@]}"; do
        # Get yesterday's and today's earliest TTL for comparison
        prev_ttl=$(grep "$server" "$previous_day" | head -1 | cut -d',' -f5)
        today_ttl=$(grep "$server" "$SUMMARY_CSV" | head -1 | cut -d',' -f5)
        
        if [[ -n "$prev_ttl" && -n "$today_ttl" && "$prev_ttl" != "N/A" && "$today_ttl" != "N/A" ]]; then
          # Check if numeric and if yes, calculate decrease
          if [[ "$prev_ttl" =~ ^[0-9]+$ && "$today_ttl" =~ ^[0-9]+$ ]]; then
            decrease=$((prev_ttl - today_ttl))
            ttl_decreases+="$server: $decrease seconds\n"
          fi
        fi
      done
    fi
    
    # Write daily summary
    # Count number of domains and servers
    domain_count=$(echo "${DOMAINS[@]}" | wc -w)
    server_count=$(echo "${DNS_SERVERS[@]}" | wc -w)

    # Get DNS servers with descriptions
    dns_server_info=""
    for server in "${DNS_SERVERS[@]}"; do
      # Extract the comment if available
      server_comment=$(grep -E "\"$server\"" "${SCRIPT_DIR}/config.sh" | sed -E 's/.*#(.*)/\1/' | tr -d '\r')
      dns_server_info+="  - $server $server_comment\n"
    done

    # Count total alerts
    alert_count=0
    if [ -f "${ALERTS_LOG}" ]; then
      alert_count=$(wc -l < "${ALERTS_LOG}")
    fi

    # Count certificate checks
    cert_count=0
    if [ -d "${CERT_DIR}" ]; then
      cert_count=$(find "${CERT_DIR}" -name "*.pem" | wc -l)
    fi

    # Check mirror HTTPS status
    https_report="${DATA_DIR}/https/mirror_https_report.md"
    mirror_summary=""
    if [ -f "$https_report" ]; then
      # First try to extract the Summary section
      summary_section=$(awk '/### Summary/,/###/' "$https_report" 2>/dev/null)

      if [ -n "$summary_section" ]; then
        # Extract the bullet points that start with -
        mirror_summary=$(echo "$summary_section" | grep "^-" | sed 's/^/  /')
      else
        # Fallback to simpler extraction
        mirror_summary=$(grep -A6 "Findings" "$https_report" | grep "^\-" | sed 's/^/  /')
      fi

      # If still empty, show a message
      if [ -z "$mirror_summary" ]; then
        mirror_summary="  Mirror HTTPS report exists but couldn't extract statistics"
      fi
    else
      mirror_summary="  No mirror HTTPS status report found"
    fi

    cat > "${DATA_DIR}/daily_summary.txt" << EOF
DNS Poisoning Monitoring Summary for ${DATE_STR}
================================================

## Monitoring Statistics
- Queries performed: $total_queries
- Domains monitored: $domain_count
- DNS servers checked: $server_count
- Alerts generated: $alert_count
- Certificates captured: $cert_count

## DNS Servers Monitored
$(echo -e "$dns_server_info")

## Poisoning Status
- Poisoned responses detected: $poisoned_count

$(if [ $poisoned_count -gt 0 ]; then
  echo "Unique TTLs observed for poisoned NS records:"
  echo "$(echo "$unique_ttls" | sed 's/^/- /')"
  echo ""
  echo "TTL decreases since yesterday:"
  echo "$(echo -e "$ttl_decreases")"
else
  echo "No poisoning detected in this monitoring run."
  echo ""
  echo "This could be because:"
  echo "- The poisoning attack has stopped or is intermittent"
  echo "- The DNS servers are no longer vulnerable or have been patched"
  echo "- DNS records for monitored domains have been corrected"
  echo "- The monitoring configuration needs adjustment"
fi)

## Mirror HTTPS Status
$mirror_summary

## Analysis Recommendations
$(if [ $poisoned_count -gt 0 ]; then
  echo "- Check if TTLs decrease linearly, suggesting fixed poisoning intervals"
  echo "- Look for regular patterns in TTL resets, indicating when poisoning occurs"
  echo "- Monitor for changes in nameservers or IPs, which may reveal attacker pivots"
else
  echo "- Continue monitoring to detect if poisoning resumes"
  echo "- Consider adjusting monitoring schedule for better coverage"
  echo "- Verify DNS server configurations match known vulnerable settings"
  echo "- Consider expanding domain list to increase detection probability"
fi)

## Reference Files
- Detailed query results: ${RAW_DIR}
- Alerts and detected changes: ${ALERTS_LOG}
- Raw data analysis: ${SUMMARY_CSV}
$(if [ -f "$https_report" ]; then echo "- Mirror HTTPS report: $https_report"; fi)
EOF
  fi
}