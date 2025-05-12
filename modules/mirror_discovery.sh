#!/bin/bash
#
# mirror_discovery.sh - Mirror URL discovery and validation
# Part of the Digital Pacific DNS Poisoning investigation (May 2025)
#
# This module provides functions for discovering and validating mirror URLs
#

# Ensure the script is being sourced, not executed directly
if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
  echo "Error: This script should be sourced, not executed directly."
  echo "Usage: source mirror_discovery.sh"
  exit 1
fi

# Default mirror list URL
DEFAULT_MIRRORS_URL="https://mirror.digitalpacific.com.au/?page=mirrors"

# Fetch mirror URLs from a Digital Pacific mirrors page
# Parameters:
#   $1 - Mirror list URL (optional, defaults to DEFAULT_MIRRORS_URL)
# Returns: Newline-separated list of mirror URLs
fetch_mirror_list() {
  local mirrors_url="${1:-$DEFAULT_MIRRORS_URL}"

  echo "Fetching mirror list from $mirrors_url..." >&2

  # Download the mirror list page and extract HTTP URLs
  local html_content=$(curl -s "$mirrors_url")

  # Extract URLs and clean up - look for href values with domains ending in mirror.digitalpacific.com.au
  local mirrors=$(echo "$html_content" | grep -o 'href="http://[^"]*\.mirror\.digitalpacific\.com\.au[^"]*"' |
                  sed 's/href="//g' | sed 's/"//g' |
                  grep -o '^http://[^<]*' | # Remove any HTML that might be included
                  sort | uniq)

  if [ -z "$mirrors" ]; then
    echo "Error: Could not fetch mirror list or no mirrors found." >&2

    # Fallback to direct domain list if available
    if [ -n "${MIRROR_DOMAINS[*]}" ]; then
      echo "Using configured mirror domains as fallback." >&2
      for domain in "${MIRROR_DOMAINS[@]}"; do
        echo "http://${domain}"
      done
      return 0
    fi

    return 1
  fi

  echo "Found $(echo "$mirrors" | wc -l) mirrors to check." >&2
  echo "$mirrors"
}

# Check if a URL redirects to HTTPS
# Parameters:
#   $1 - URL to check
#   $2 - Timeout in seconds (optional, defaults to 10)
#   $3 - Results file to append to (optional)
# Returns: CSV formatted result line (url,status_code,redirects_to_https,redirect_url)
check_redirect() {
  local url="$1"
  local timeout="${2:-10}"
  local results_file="$3"

  # Validate URL format - must start with http:// and not contain any HTML or trailing characters
  if [[ ! "$url" =~ ^http://[a-zA-Z0-9\.\-]+\.[a-zA-Z0-9\.\-]+(/.*)?$ ]]; then
    echo "Warning: Invalid URL format: $url" >&2
    # Return a formatted error result
    local output_line="$url,invalid_url,No,invalid_format"
    echo "$output_line"

    # Add to results file if provided
    if [ -n "$results_file" ]; then
      echo "$output_line" >> "$results_file"
    fi
    return 1
  fi

  echo "Checking: $url" >&2

  # Get HTTP status code and redirect URL with error handling
  local curl_result
  curl_result=$(curl -s -m "$timeout" -o /dev/null -w "%{http_code},%{redirect_url}" "$url" 2>/dev/null) || {
    echo "Warning: curl failed for $url" >&2
    local output_line="$url,connection_error,No,failed_to_connect"
    echo "$output_line"

    # Add to results file if provided
    if [ -n "$results_file" ]; then
      echo "$output_line" >> "$results_file"
    fi
    return 1
  }

  status_code=$(echo "$curl_result" | cut -d',' -f1)
  redirect_url=$(echo "$curl_result" | cut -d',' -f2-)

  # Check if redirect URL starts with https://
  if [[ -n "$redirect_url" && "$redirect_url" == https://* ]]; then
    redirects_to_https="Yes"
  else
    redirects_to_https="No"
  fi

  # Output result
  local output_line="$url,$status_code,$redirects_to_https,$redirect_url"
  echo "$output_line"

  # Add to results file if provided
  if [ -n "$results_file" ]; then
    echo "$output_line" >> "$results_file"
  fi
}

# Check multiple mirrors for HTTP to HTTPS redirects
# Parameters:
#   $1 - Newline-separated list of mirror URLs
#   $2 - Timeout in seconds (optional, defaults to 10)
#   $3 - Results file to save to (optional)
# Returns:
#   - String of newline-separated CSV result lines
#   - Sets HTTPS_COUNT and TOTAL_COUNT variables
check_mirrors_https() {
  local mirrors="$1"
  local timeout="${2:-10}"
  local results_file="$3"

  # Initialize counters
  HTTPS_COUNT=0
  TOTAL_COUNT=0
  VALID_COUNT=0

  # Initialize results string
  local results=""

  # Check if mirrors is empty - provide fallback mirror list
  if [ -z "$mirrors" ]; then
    echo "No mirrors provided to check_mirrors_https, using fallback mirror list" >&2
    mirrors="http://fedora.mirror.digitalpacific.com.au/fedora/
http://ubuntu.mirror.digitalpacific.com.au/ubuntu/
http://debian.mirror.digitalpacific.com.au/debian/"
  fi

  # Count total number of URLs to check
  total_urls=$(echo "$mirrors" | grep -c "^http://" || echo 0)
  echo "Found $total_urls mirrors to check" >&2

  # Check each mirror for redirections
  while IFS= read -r mirror; do
    # Skip empty lines and non-URLs
    if [[ -z "$mirror" || ! "$mirror" =~ ^http:// ]]; then
      continue
    fi

    result=$(check_redirect "$mirror" "$timeout" "$results_file")
    check_status=$?

    # Append to results string with newline
    if [ -z "$results" ]; then
      results="$result"
    else
      results="${results}"$'\n'"${result}"
    fi

    # Update counters - only count valid results
    if [ $check_status -eq 0 ]; then
      VALID_COUNT=$((VALID_COUNT + 1))
      if [[ "$result" == *",Yes,"* ]]; then
        HTTPS_COUNT=$((HTTPS_COUNT + 1))
      fi
    fi

    # Always increment total count for statistics
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
  done <<< "$mirrors"

  # Summary
  echo "Checked $TOTAL_COUNT URLs, of which $VALID_COUNT were valid" >&2
  echo "Found $HTTPS_COUNT URLs that redirect to HTTPS" >&2

  # Export the results
  echo "$results"
}

# Generate a markdown report of mirror HTTPS redirection analysis
# Parameters:
#   $1 - String of CSV-formatted result lines (can be multiline)
#   $2 - HTTPS count
#   $3 - Total count
# Returns: Markdown formatted report with proper line endings
generate_mirror_report() {
  local results="$1"
  local https_count="$2"
  local total_count="$3"
  
  # Begin markdown output with explicit line endings
  echo "# Digital Pacific Mirror HTTPS Redirect Analysis"
  echo ""
  echo "*Analysis Date: $(date)*"
  echo ""
  echo "## Introduction"
  echo ""
  echo "This report analyzes the HTTP to HTTPS redirection behavior of Digital Pacific's mirror repositories."
  echo "In the context of the DNS poisoning attack affecting Superloop DNS servers, proper HTTPS usage"
  echo "is critical to prevent undetected man-in-the-middle attacks."
  echo ""
  echo "## Methodology"
  echo ""
  echo "The script performs the following steps:"
  echo ""
  echo "1. Fetches the mirror list from $DEFAULT_MIRRORS_URL"
  echo "2. Extracts all HTTP URLs for *.mirror.digitalpacific.com.au domains"
  echo "3. Tests each URL for HTTP to HTTPS redirection using curl"
  echo "4. Analyzes the results to identify security vulnerabilities"
  echo ""
  echo "## Findings"
  echo ""
  echo "### Summary"
  echo ""
  echo "- **Total mirrors checked**: $total_count"
  echo "- **Mirrors that redirect to HTTPS**: $https_count"
  echo "- **Mirrors that DO NOT redirect to HTTPS**: $((total_count - https_count))"

  # Calculate percentage with division by zero protection
  if [[ $total_count -gt 0 ]]; then
    unprotected_percent=$(( (total_count - https_count) * 100 / total_count ))
    echo "- **Percentage unprotected**: ${unprotected_percent}%"
  else
    echo "- **Percentage unprotected**: N/A (no mirrors checked)"
  fi
  echo ""
  echo "### Detailed Results"
  echo ""
  echo "| Mirror URL | HTTP Status | Redirects to HTTPS | Redirect URL |"
  echo "|------------|-------------|-------------------|---------------|"
  
  # Output results in markdown table format with explicit line endings
  echo "$results" | while IFS=',' read -r url status redirects redirect_url; do
    echo "| $url | $status | $redirects | $redirect_url |"
  done

  # Finish markdown output with explicit line endings
  echo ""
  echo "## Security Implications"
  echo ""

  # Display percentage with division by zero protection
  if [[ $total_count -gt 0 ]]; then
    unprotected_percent=$(( (total_count - https_count) * 100 / total_count ))
    echo "The analysis reveals that **${unprotected_percent}%** of Digital Pacific mirrors"
    echo "do not redirect to HTTPS. This represents a significant security vulnerability, especially in the"
    echo "context of the observed DNS poisoning attack targeting Superloop DNS servers."
  else
    echo "No mirrors were checked in this run, so no security assessment could be made."
    echo "This could be due to connectivity issues or because no mirror URLs were provided."
  fi
  echo ""
  echo "When mirror domains do not enforce HTTPS:"
  echo ""
  echo "1. Users have no browser security indicators to warn them when connecting to a malicious server"
  echo "2. DNS poisoning attacks can redirect users to malicious mirrors without detection"
  echo "3. Downloaded software packages could be modified in transit without the user's knowledge"
  echo ""
  echo "## Recommendations"
  echo ""
  echo "1. Digital Pacific should update all mirror links to use HTTPS instead of HTTP"
  echo "2. Automatic HTTP to HTTPS redirections should be implemented across all mirrors"
  echo "3. Consider implementing HSTS (HTTP Strict Transport Security) for all mirror domains"
  echo "4. Users should manually use HTTPS when accessing these mirrors until fixed"
  echo "5. Always verify checksums of downloaded packages"
  echo ""
  echo "## References"
  echo ""
  echo "- [DNS Poisoning Incident Report: Superloop DNS Servers](../README.md)"
  echo "- [Mirror List Security Investigation](../analysis/mirror-list-investigation.md)"
}