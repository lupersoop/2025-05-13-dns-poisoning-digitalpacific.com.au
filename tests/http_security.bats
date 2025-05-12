#!/usr/bin/env bats

load test_helper

setup() {
  # Set up test environment with proper directories
  setup_test_environment

  # Load the modules
  source "${MODULES_DIR}/http_security.sh"
}

teardown() {
  # Clean up test environment
  reset_test_environment
}

@test "check_https_redirect detects https redirect" {
  # Mock curl to return a redirect to HTTPS
  function curl() {
    echo "301,https://example.com"
  }
  export -f curl

  # Test with our mocked curl
  run check_https_redirect "http://example.com" 5

  # Print debug output
  echo "Output: $output"

  [ "$status" -eq 0 ]
  [[ "$output" == *",Yes,"* ]]
}

@test "check_https_redirect detects missing redirect" {
  # Mock curl to return a non-redirect response
  function curl() {
    echo "200,"
  }
  export -f curl
  
  run check_https_redirect "http://nonexistent.example.com" 1
  
  [ "$status" -eq 0 ]
  [[ "$output" == *",No,"* ]]
}

@test "check_security_headers detects missing headers" {
  # Mock curl to return headers without security headers
  function curl() {
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: text/html"
    echo "Server: nginx"
  }
  export -f curl
  
  run check_security_headers "https://example.com" 1
  
  [ "$status" -eq 0 ]
  [[ "$output" != "None" ]]
  [[ "$output" == *"HSTS"* ]]
}

@test "check_security_headers detects all headers" {
  # Mock curl to return all security headers
  function curl() {
    echo "HTTP/1.1 200 OK"
    echo "Content-Type: text/html"
    echo "Strict-Transport-Security: max-age=31536000"
    echo "X-Content-Type-Options: nosniff"
    echo "X-Frame-Options: DENY"
    echo "Content-Security-Policy: default-src 'self'"
    echo "X-XSS-Protection: 1; mode=block"
  }
  export -f curl
  
  run check_security_headers "https://example.com" 1
  
  [ "$status" -eq 0 ]
  [[ "$output" == "None" ]]
}

@test "check_hsts detects enabled HSTS" {
  # Mock curl to return HSTS header
  function curl() {
    echo "HTTP/1.1 200 OK"
    echo "Strict-Transport-Security: max-age=31536000"
  }
  export -f curl
  
  run check_hsts "https://example.com" 1
  
  [ "$status" -eq 0 ]
}

@test "check_hsts detects missing HSTS" {
  # Mock curl to return no HSTS header
  function curl() {
    echo "HTTP/1.1 200 OK"
    echo "Server: nginx"
  }
  export -f curl
  
  run check_hsts "https://example.com" 1
  
  [ "$status" -eq 1 ]
}

@test "validate_domains_security produces correct CSV" {
  # Mock curl to return predictable responses
  function check_https_redirect() {
    echo "200,Yes,https://example.com/"
  }
  export -f check_https_redirect
  
  function check_security_headers() {
    echo "HSTS,CSP"
  }
  export -f check_security_headers
  
  function check_hsts() {
    return 1
  }
  export -f check_hsts
  
  function check_mixed_content() {
    return 0
  }
  export -f check_mixed_content
  
  # Create test domains array
  local domains=("example.com")
  
  # Test file
  local output_file="${TEST_DATA_DIR}/security_results.csv"

  run validate_domains_security "${domains[@]}" 1 "$output_file"

  [ "$status" -eq 0 ]
  [ -f "$output_file" ]
  
  # Check header line
  if [ -f "$output_file" ]; then
    run head -n 1 "$output_file"
    [[ "$output" == "Domain,HTTPS Redirect,Status Code,Redirect URL,Missing Security Headers,HSTS Enabled,Mixed Content" ]]

    # Check data line
    run tail -n 1 "$output_file"
  else
    echo "Test file not found: $output_file"
    false
  fi
  [[ "$output" == "example.com,Yes,200,https://example.com/,HSTS,CSP,No,No" ]]
}