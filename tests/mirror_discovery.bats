#!/usr/bin/env bats
#
# Tests for the mirror_discovery.sh module
#

load test_helper

setup() {
  # Set up test environment with proper directories
  setup_test_environment
  
  # Create test mirror HTML using helper function
  create_test_mirror_html
  
  # Load the module being tested
  source "${MODULES_DIR}/mirror_discovery.sh"
}

teardown() {
  # Clean up test environment
  reset_test_environment
}

@test "fetch_mirror_list extracts mirror URLs" {
  # Mock curl to return our test HTML
  function curl() {
    cat "${TEST_FIXTURES_DIR}/html/mirrors.html"
  }
  export -f curl
  
  run fetch_mirror_list "http://example.com/mirrors"
  
  [ "$status" -eq 0 ]
  [ "$(echo "$output" | grep -c "^http://")" -eq 3 ]
  [[ "$output" == *"http://fedora.mirror.digitalpacific.com.au/fedora/"* ]]
  [[ "$output" == *"http://ubuntu.mirror.digitalpacific.com.au/ubuntu/"* ]]
  [[ "$output" == *"http://debian.mirror.digitalpacific.com.au/debian/"* ]]
}

@test "check_redirect detects redirect" {
  # Mock curl to return a redirect
  function curl() {
    echo "301,https://example.com"
  }
  export -f curl

  run check_redirect "http://example.com" 1
  
  # Write output to test outputs directory for debugging
  echo "$output" > "${TEST_OUTPUTS_DIR}/check_redirect_output.txt"

  [ "$status" -eq 0 ]
  [[ "$output" == *"http://example.com"* ]]
  [[ "$output" == *"301"* ]]
  [[ "$output" == *"Yes"* ]]
  [[ "$output" == *"https://example.com"* ]]
}

@test "check_redirect handles invalid URLs" {
  run check_redirect "http://invalid<domain>.com" 1
  
  [ "$status" -eq 1 ]
  [[ "$output" == *"invalid_url"* ]]
  [[ "$output" == *"No"* ]]
  [[ "$output" == *"invalid_format"* ]]
}

@test "check_mirrors_https analyzes https redirects" {
  # Create test results file
  local results_file="${TEST_DATA_DIR}/mirror_redirects.csv"
  echo "Mirror URL,HTTP Status,Redirects to HTTPS,Redirect URL" > "$results_file"

  # Mock check_redirect to return predictable results
  function check_redirect() {
    local url="$1"
    local timeout="$2"

    if [[ "$url" == *"fedora"* ]]; then
      echo "$url,301,Yes,https://fedora.example.com"
      return 0
    elif [[ "$url" == *"ubuntu"* ]]; then
      echo "$url,200,No,"
      return 0
    else
      echo "$url,connection_error,No,failed_to_connect"
      return 1
    fi
  }
  export -f check_redirect

  # Create test input
  local test_mirrors="http://fedora.mirror.digitalpacific.com.au/fedora/
http://ubuntu.mirror.digitalpacific.com.au/ubuntu/
http://invalid.mirror.digitalpacific.com.au/"

  # Run the function and capture output
  run check_mirrors_https "$test_mirrors" 1 "$results_file"

  [ "$status" -eq 0 ]
  [[ "$output" == *"http://fedora.mirror.digitalpacific.com.au/fedora/,301,Yes,https://fedora.example.com"* ]]
  [[ "$output" == *"http://ubuntu.mirror.digitalpacific.com.au/ubuntu/,200,No,"* ]]

  # The variables HTTPS_COUNT and TOTAL_COUNT are not accessible in this context
  # after using 'run' because 'run' executes in a subshell
  # Instead, check the output for expected counters
  [[ "$output" == *"Found 1 URLs that redirect to HTTPS"* ]] || \
  [[ "$output" == *"Checked 3 URLs"* ]]
}

@test "generate_mirror_report creates markdown report" {
  # Create test data for a single result for simplicity
  local test_result="http://example1.com,301,Yes,https://example1.com"
  local test_https_count=1
  local test_total_count=1
  
  # Run the function with our test data
  run generate_mirror_report "$test_result" "$test_https_count" "$test_total_count"
  
  # Write output to test outputs directory for debugging
  echo "$output" > "${TEST_OUTPUTS_DIR}/mirror_report_output.md"
  
  # Check status
  [ "$status" -eq 0 ]
  
  # Check for key components of the report 
  [[ "$output" == *"# Digital Pacific Mirror HTTPS Redirect Analysis"* ]]
  [[ "$output" == *"**Total mirrors checked**: $test_total_count"* ]]
  [[ "$output" == *"**Mirrors that redirect to HTTPS**: $test_https_count"* ]]
  [[ "$output" == *"**Mirrors that DO NOT redirect to HTTPS**: 0"* ]]
  
  # Check for table headers
  [[ "$output" == *"| Mirror URL | HTTP Status | Redirects to HTTPS | Redirect URL |"* ]]
  
  # Check for example URL in the table
  [[ "$output" == *"http://example1.com"* ]]
  [[ "$output" == *"301"* ]]
  [[ "$output" == *"Yes"* ]]
  
  # More basic checks
  [[ "$output" == *"## Security Implications"* ]]
  [[ "$output" == *"## Recommendations"* ]]
}

@test "generate_mirror_report handles multiple URLs" {
  # Create test data for multiple results
  local test_results="http://example1.com,301,Yes,https://example1.com
http://example2.com,200,No,"
  local test_https_count=1
  local test_total_count=2
  
  # Run the function with our test data
  run generate_mirror_report "$test_results" "$test_https_count" "$test_total_count"
  
  # Write output to test outputs directory for debugging
  echo "$output" > "${TEST_OUTPUTS_DIR}/mirror_report_multiple_output.md"
  
  # Check for percentage calculations
  [[ "$output" == *"**Percentage unprotected**: 50%"* ]]
  
  # Check for both URLs in the table
  [[ "$output" == *"| http://example1.com | 301 | Yes | https://example1.com |"* ]]
  [[ "$output" == *"| http://example2.com | 200 | No |  |"* ]]
}