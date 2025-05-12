#!/usr/bin/env bats

load test_helper

setup() {
  # Set up test environment with proper directories
  setup_test_environment

  # Create test dig output files
  cat > "${TEST_DATA_DIR}/dig_ns_output.txt" << EOF
; <<>> DiG 9.16.1-Ubuntu <<>> NS digitalpacific.com.au @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
digitalpacific.com.au. 3600 IN NS ns1.digitalpacific.com.au.
digitalpacific.com.au. 3600 IN NS ns2.digitalpacific.com.au.

;; ADDITIONAL SECTION:
ns1.digitalpacific.com.au. 3600 IN A 203.16.232.250

;; Query time: 25 msec
;; SERVER: a.1.1.1#53(1.1.1.1)
;; WHEN: Tue May 13 01:50:08 AEST 2025
;; MSG SIZE  rcvd: 92
EOF

  cat > "${TEST_DATA_DIR}/dig_a_output.txt" << EOF
; <<>> DiG 9.16.1-Ubuntu <<>> A digitalpacific.com.au @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 67890
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
digitalpacific.com.au. 300 IN A 203.16.232.200

;; AUTHORITY SECTION:
digitalpacific.com.au. 3600 IN NS ns1.digitalpacific.com.au.

;; Query time: 45 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Tue May 13 01:50:11 AEST 2025
;; MSG SIZE  rcvd: 81
EOF

  cat > "${TEST_DATA_DIR}/dig_poisoned_output.txt" << EOF
; <<>> DiG 9.16.1-Ubuntu <<>> NS digitalpacific.com.au @119.40.106.35
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54321
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
digitalpacific.com.au. 600 IN NS ns1.has.email.
digitalpacific.com.au. 600 IN NS ns2.has.email.

;; ADDITIONAL SECTION:
ns1.has.email. 300 IN A 192.0.2.1

;; Query time: 15 msec
;; SERVER: 119.40.106.35#53(119.40.106.35)
;; WHEN: Tue May 13 01:50:06 AEST 2025
;; MSG SIZE  rcvd: 98
EOF

  # Load the modules
  source "${MODULES_DIR}/utils.sh"
  source "${MODULES_DIR}/dns_analysis.sh"
}

teardown() {
  # Clean up test environment
  reset_test_environment
}

@test "extract_ttl correctly extracts TTL from dig output" {
  run extract_ttl "$(cat ${TEST_DATA_DIR}/dig_ns_output.txt)"

  [ "$status" -eq 0 ]
  [ "$output" = "3600" ]
}

@test "extract_ttl returns none_found for missing TTL" {
  run extract_ttl "ERROR: no servers could be reached"

  [ "$status" -eq 0 ]
  [ "$output" = "none_found" ]
}

@test "extract_nameservers returns correct NS records" {
  run extract_nameservers "$(cat ${TEST_DATA_DIR}/dig_ns_output.txt)" "NS"

  [ "$status" -eq 0 ]
  [[ "$output" == *"ns1.digitalpacific.com.au"* ]]
  [[ "$output" == *"ns2.digitalpacific.com.au"* ]]
}

@test "extract_nameservers returns authority NS for A record" {
  run extract_nameservers "$(cat ${TEST_DATA_DIR}/dig_a_output.txt)" "A"

  [ "$status" -eq 0 ]
  [[ "$output" == *"ns1.digitalpacific.com.au"* ]]
}

@test "extract_ips returns correct A record" {
  run extract_ips "$(cat ${TEST_DATA_DIR}/dig_a_output.txt)" "A"

  [ "$status" -eq 0 ]
  echo "Output: $output"
  [[ "$output" == *"203.16.232.200"* ]]
}

@test "extract_response_time returns query time" {
  run extract_response_time "$(cat ${TEST_DATA_DIR}/dig_ns_output.txt)"

  [ "$status" -eq 0 ]
  [ "$output" = "25" ]
}

@test "check_for_poisoning detects has.email nameservers" {
  run check_for_poisoning "digitalpacific.com.au" "NS" "119.40.106.35" "ns1.has.email,ns2.has.email" "600"
  
  [ "$status" -eq 1 ]
  [ -f "${ALERTS_LOG}" ]
  run cat "${ALERTS_LOG}"
  [[ "$output" == *"POISONING DETECTED"* ]]
}

@test "check_for_poisoning returns false for legitimate nameservers" {
  run check_for_poisoning "digitalpacific.com.au" "NS" "1.1.1.1" "ns1.digitalpacific.com.au,ns2.digitalpacific.com.au" "3600"
  
  [ "$status" -eq 0 ]
}

@test "extract_suspicious_domains identifies has.email domains" {
  # Reset the SUSPICIOUS_DOMAINS global array
  SUSPICIOUS_DOMAINS=()
  export SUSPICIOUS_DOMAINS

  # Create a wrapper function to properly handle array updates
  function test_extract_domains() {
    extract_suspicious_domains "ns1.has.email,ns2.has.email"
    # Output the array size so we can check it
    echo "Array size: ${#SUSPICIOUS_DOMAINS[@]}"
    # Output array contents
    echo "Elements: ${SUSPICIOUS_DOMAINS[*]}"
  }

  run test_extract_domains

  [ "$status" -eq 0 ]
  echo "Output: $output"
  [[ "$output" == *"Array size: 2"* ]]
  [[ "$output" == *"Elements: "* ]]
  [[ "$output" == *"ns1.has.email"* ]]
}