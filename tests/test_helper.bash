#!/usr/bin/env bash
#
# Test helpers for the DNS monitoring system
#

# Export variables for testing
export LANG=C.UTF-8
export TERM=dumb
export COLUMNS=80
export LINES=25

# Test Paths
export MONITORING_ROOT="${BATS_TEST_DIRNAME}/.."
export MODULES_DIR="${MONITORING_ROOT}/modules"
export TEST_FIXTURES_DIR="${BATS_TEST_DIRNAME}/fixtures"
export TEST_OUTPUTS_DIR="${BATS_TEST_DIRNAME}/outputs"
export TEST_DATA_DIR="${BATS_TEST_DIRNAME}/temp/test_data"

# Ensure test directories exist
mkdir -p "${TEST_FIXTURES_DIR}/dig" "${TEST_FIXTURES_DIR}/html" "${TEST_FIXTURES_DIR}/http" "${TEST_FIXTURES_DIR}/certs" "${TEST_FIXTURES_DIR}/outputs"
mkdir -p "${TEST_OUTPUTS_DIR}" "${TEST_DATA_DIR}" "${BATS_TEST_DIRNAME}/temp/test_data"

# Make sure we preserve our fixture files if they exist
if [ ! -f "${TEST_FIXTURES_DIR}/certs/example_com_at_1_1_1_1.pem" ]; then
  # Create sample certificate fixtures for tests that need them
  echo "Creating sample certificate fixtures..."
  echo "Sample certificate data" > "${TEST_FIXTURES_DIR}/certs/example_com_at_1_1_1_1.pem"
  echo "Certificate info data" > "${TEST_FIXTURES_DIR}/certs/example_com_at_1_1_1_1_info.txt"
fi

if [ ! -f "${TEST_FIXTURES_DIR}/http/example_com_http_at_1_1_1_1.html" ]; then
  # Create sample HTTP content fixtures
  echo "Creating sample HTTP content fixtures..."
  echo "<html></html>" > "${TEST_FIXTURES_DIR}/http/example_com_http_at_1_1_1_1.html"
  echo "Content-Type: text/html" > "${TEST_FIXTURES_DIR}/http/example_com_http_at_1_1_1_1_headers.txt"
  echo "md5sum_placeholder" > "${TEST_FIXTURES_DIR}/http/example_com_http_at_1_1_1_1.html.md5"
fi

# Default test values - using real domains from our monitoring
export TEST_DOMAIN="digitalpacific.com.au"
export TEST_IP="203.16.232.200"
export TEST_NS="ns1.digitalpacific.com.au"
export TEST_DNS_SERVER="1.1.1.1"
export TEST_TIMEOUT=1
export TEST_MIRROR_DOMAIN="fedora.mirror.digitalpacific.com.au"
export TEST_MIRROR_IP="101.0.120.90"

# Configure test environment to use test directories
setup_test_environment() {
  # Override environment variables to use test directories
  export DATA_DIR="${TEST_DATA_DIR}/$(date +"%Y-%m-%d")"
  export RAW_DIR="${DATA_DIR}/raw/$(date +"%H-%M-%S")"
  export CERT_DIR="${DATA_DIR}/certificates"
  export CONTENT_DIR="${DATA_DIR}/content"
  export WHOIS_DIR="${DATA_DIR}/whois"
  export SYSTEM_DIR="${DATA_DIR}/system"
  export HTTPS_DIR="${DATA_DIR}/https"
  export ALERTS_LOG="${DATA_DIR}/alerts.log"
  export SUMMARY_CSV="${DATA_DIR}/summary.csv"
  
  # Create data directories for tests
  mkdir -p "${RAW_DIR}" "${CERT_DIR}" "${CONTENT_DIR}" "${WHOIS_DIR}" "${SYSTEM_DIR}" "${HTTPS_DIR}"
  
  # Initialize files if needed
  touch "${ALERTS_LOG}"
  
  if [ ! -f "${SUMMARY_CSV}" ]; then
    echo "Timestamp,Domain,QueryType,DNSServer,TTL,Nameservers,IPs,ResponseTime,HasChanged" > "${SUMMARY_CSV}"
  fi
}

# Reset test environment - call this in teardown functions
reset_test_environment() {
  # Clean up data directory created by this test
  if [[ -d "${TEST_DATA_DIR}" && "${TEST_DATA_DIR}" == *"test_data"* ]]; then
    rm -rf "${TEST_DATA_DIR}"
  fi
}

# Helper function to mock files within the test
mock_file() {
  local path="$1"
  local content="$2"
  mkdir -p "$(dirname "$path")"
  echo "$content" > "$path"
  echo "$path"
}

# Helper function to create test dig output
create_test_dig_output() {
  local query_type="$1"
  local domain="$2"
  local result="$3"
  local server="${4:-$TEST_DNS_SERVER}"
  
  local output_file="${TEST_FIXTURES_DIR}/dig/dig_${query_type}_${domain//\./_}_${server//\./_}.txt"
  
  cat > "$output_file" << EOF
; <<>> DiG 9.16.1-Ubuntu <<>> ${query_type} ${domain}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
${domain}. 300 IN ${query_type} ${result}

;; Query time: 25 msec
;; SERVER: ${server}#53(${server})
;; WHEN: Tue May 13 01:50:08 AEST 2025
;; MSG SIZE  rcvd: 92
EOF

  echo "$output_file"
}

# Helper function to create poisoned test dig output
create_poisoned_dig_output() {
  local query_type="$1"
  local domain="$2"
  local server="${3:-$TEST_DNS_SERVER}"
  
  local output_file="${TEST_FIXTURES_DIR}/dig/poisoned_${query_type}_${domain//\./_}_${server//\./_}.txt"
  
  cat > "$output_file" << EOF
; <<>> DiG 9.16.1-Ubuntu <<>> ${query_type} ${domain}
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 2, ADDITIONAL: 1

;; AUTHORITY SECTION:
${domain}. 3600 IN NS ns1.has.email.
${domain}. 3600 IN NS ns2.has.email.

;; ADDITIONAL SECTION:
ns1.has.email. 3600 IN A 185.159.82.210
ns2.has.email. 3600 IN A 185.159.82.219

;; Query time: 35 msec
;; SERVER: ${server}#53(${server})
;; WHEN: Tue May 13 01:55:12 AEST 2025
;; MSG SIZE  rcvd: 123
EOF

  echo "$output_file"
}

# Helper to create test HTML for mirror list
create_test_mirror_html() {
  local output_file="${TEST_FIXTURES_DIR}/html/mirrors.html"

  cat > "$output_file" << EOF
<html>
<body>
  <h1>Digital Pacific Mirrors</h1>
  <ul>
    <li><a href="http://fedora.mirror.digitalpacific.com.au/fedora/">Fedora Mirror</a></li>
    <li><a href="http://ubuntu.mirror.digitalpacific.com.au/ubuntu/">Ubuntu Mirror</a></li>
    <li><a href="http://debian.mirror.digitalpacific.com.au/debian/">Debian Mirror</a></li>
  </ul>
</body>
</html>
EOF

  echo "$output_file"
}

# Helper to get sample certificate file
get_test_certificate() {
  local domain="$1"
  local ip="$2"

  # Default to example.com @ 1.1.1.1 if not specified
  domain="${domain:-example.com}"
  ip="${ip:-1.1.1.1}"

  # Normalize domain and IP for filename
  local domain_safe="${domain//\./_}"
  local ip_safe="${ip//\./_}"

  # Return path to the certificate file, creating it if needed
  local cert_file="${TEST_FIXTURES_DIR}/certs/${domain_safe}_at_${ip_safe}.pem"

  if [ ! -f "$cert_file" ]; then
    # Create a placeholder certificate
    echo "-----BEGIN CERTIFICATE-----
MIIFYDCCA0igAwIBAgIQCgFCgAAAABHRRrgcv/d+GzANBgkqhkiG9w0BAQsFADBS
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVEVTVDELMAkGA1UEBxMCVEVTVDERMA8G
A1UEChMIVEVTVCBJTkMxFjAUBgNVBAMTDVRlc3QgUm9vdCBDQSAyMB4XDTIwMDQx
OTIxMDAwMFoXDTI1MDQxOTIxMDAwMFowUjELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AlRFU1QxCzAJBgNVBAcTAlRFU1QxETAPBgNVBAoTCFRFU1QgSU5DMRYwFAYDVQQD
DA0qLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
2l+AvAQH/Qm20HooK4JTPEwwKl+G1JrLEf3BBDSzYGm3GBo7Dta/QUwOA5qptj/T
DFBX/V5ZBMykT7Ux9IzBl5lrOYXyfbQNrwkJY9ZaZ6GQZUbdIJgX+UbHdFDr+3MB
vUvB4IFP+ZcG7AN0fNFQDyqVw/a/xqMYVkCXEdPCb32rZYLRcheZopbBfmj34TQC
v8HseBmK7PkBqQOxfGEuNw1OMT6FuJiKRJkGtL4K7ME8TQhsLUUAuPLPMTLQtZBK
Zy2JcuNJwZRfXpkxhQJVHYvzHOYNIEOwJl+nuHmJGpuZ8pFBk/KnPJRQsLEnUUFt
LJdHZu2yK1QbdhR+QZjgkQIDAQABo4IBOTCCATUwHwYDVR0jBBgwFoAUGqJd3bQg
kZYOI5uz14bW0r13BJ0wHQYDVR0OBBYEFDCJLwdDa3APoLLRXa0UPsZxROxkMA4G
A1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwbgYD
VR0fBGcwZTBjoGGgX4ZdaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
VExTUlNBU0hBMjU2MjAyMENBLTQuY3JsMGOgYaBfhmdodHRwOi8vY3JsNC5kaWdp
Y2VydC5jb20vRGlnaUNlcnRUTFNSU0FTSEEyNTYyMDIwQ0EtNC5jcmwwTAYDVR0g
BEUwQzA3BglghkgBhv1sAQIwKjAoBggrBgEFBQcCARYcaHR0cDovL3d3dy5kaWdp
Y2VydC5jb20vQ1BTMAgGBmeBDAECAjANBgkqhkiG9w0BAQsFAAOCAgEAwLaUWJjG
dXUBYsYN2lCbCHLrI/R6Y6HgG3KAzb/ZieEzFTcWFA85a9DRcUO0WDorXgFzgDFl
6c0T3w4PQee1JdLL/UrnMJKO3JmGnlTTm5f0xOgV8CgCuJILlyY2x1YKQQnqPGZO
pWa/npAWqEXLWny/qbQYyIyDmYRD/IG7pQTnyCbVcSoN6m0HoXVxLEJHpXzMwqwA
/q4FBALQGhBmkwIdz/6ubBWKcJczLAVVFP2ASOQFYOqwV8z0NK1Fwal0FUzfEAwP
Z2P3NtoHeWXh6CFz3YeCJ8j+AAXs1Cpe7+N0GDVzzl+7zFzTkGkc3vTZ12zY8/9u
2Xa+t0MFQxMXK/aTvvfn9VRRCNV9VKPuJ29VPOX3cKKfRMp4h5OIQTn0er5yQkfG
1uKgN5TNH3JLGgWQVK7OLJ32Z8o5amogbI0/ACbNYQq9BcGmGNWXKnUHNnRhoQk8
Cdz1oQaZiRIYZzOsWqwZcbfcZKgD9mTTk8gG1sRDQvE1e8E+Z6BzSQkuxj6vTOEy
O4HVQ6QqCgQHx2UZCGN1QWYhXEeEn8MuiOsnHoGr/xYU/Yj4cLZer7fLcUJ8xKOw
pHVLQgKS9L0NRIJuaXy6nPF+3LCVgM2wjA+VGFu2o6N77G7JYXN3dKn/6Sz1NIOz
kTvwg3yfjgHOgmnzL7T6PKO1Lku5yr8=
-----END CERTIFICATE-----" > "$cert_file"

    # Create info file too
    local info_file="${TEST_FIXTURES_DIR}/certs/${domain_safe}_at_${ip_safe}_info.txt"
    echo "Subject: C=US, ST=TEST, L=TEST, O=TEST INC, CN=${domain}
Issuer: C=US, ST=TEST, L=TEST, O=TEST INC, CN=Test Root CA 2
Valid from: Apr 19 21:00:00 2020 GMT
Valid until: Apr 19 21:00:00 2025 GMT
SAN: DNS:*.${domain}, DNS:${domain}" > "$info_file"
  fi

  echo "$cert_file"
}

# Helper to get sample HTTP content file
get_test_http_content() {
  local domain="$1"
  local ip="$2"
  local scheme="${3:-http}"

  # Default to example.com @ 1.1.1.1 if not specified
  domain="${domain:-example.com}"
  ip="${ip:-1.1.1.1}"

  # Normalize domain and IP for filename
  local domain_safe="${domain//\./_}"
  local ip_safe="${ip//\./_}"

  # Return path to the HTML file, creating it if needed
  local html_file="${TEST_FIXTURES_DIR}/http/${domain_safe}_${scheme}_at_${ip_safe}.html"

  if [ ! -f "$html_file" ]; then
    # Create placeholder HTML
    echo "<html><head><title>Test page for ${domain}</title></head><body><h1>Test Page</h1><p>This is a test page for ${domain} via ${scheme}.</p></body></html>" > "$html_file"

    # Create headers file too
    local headers_file="${TEST_FIXTURES_DIR}/http/${domain_safe}_${scheme}_at_${ip_safe}_headers.txt"
    echo "HTTP/1.1 200 OK
Date: $(date -R)
Server: TestServer/1.0
Content-Type: text/html; charset=UTF-8
Connection: keep-alive" > "$headers_file"

    # Create MD5 file
    local md5_file="${html_file}.md5"
    md5sum "$html_file" | cut -d' ' -f1 > "$md5_file"
  fi

  echo "$html_file"
}