# DNS Poisoning Monitoring Summary for 2025-05-13

## Overview

- **Total domains monitored**: 5 (digitalpacific.com.au, fedora.mirror.digitalpacific.com.au, ubuntu.mirror.digitalpacific.com.au, debian.mirror.digitalpacific.com.au, centos.mirror.digitalpacific.com.au)
- **DNS servers queried**: 4 (1.1.1.1, 119.40.106.35, 119.40.106.36, 162.159.25.173)
- **Monitoring period**: 04:15:48 to 04:16:11 AEST
- **Suspicious domains detected**: 2 (ns1.has.email, ns2.has.email)

## DNS Poisoning Detection

### ⚠️ DNS Poisoning Detected

| Domain | DNS Server | Poisoned Nameservers | TTL | Detection Time |
|--------|------------|---------------------|-----|----------------|
| digitalpacific.com.au | 119.40.106.35 | ns1.has.email, ns2.has.email | 3600 | 04:15:48 AEST |
| digitalpacific.com.au | 119.40.106.36 | ns1.has.email, ns2.has.email | 3600 | 04:15:49 AEST |

**Technical Details**:
- DNS servers 119.40.106.35 and 119.40.106.36 (Superloop) are providing poisoned NS records for digitalpacific.com.au
- These poisoned records point to ns1.has.email and ns2.has.email with TTL of 3600 seconds
- Fraudulent nameserver returns IP 101.0.120.90 for mirror subdomains (fedora, ubuntu, debian)
- Legitimate Cloudflare nameservers (162.159.25.173, 1.1.1.1) continue to provide correct responses

**Server Anomalies Detected**:
- Unusual server software detected: Mirror servers using nginx instead of Apache
- Missing HSTS security headers on all mirror subdomains
- Missing X-Content-Type-Options security headers on all mirror subdomains

**Certificate Anomalies**:
- **SUSPICIOUS CERTIFICATE**: Domain ubuntu.mirror.digitalpacific.com.au at IP 111.90.150.116 has certificate with "has.email" subject
- **CERTIFICATE DOMAIN MISMATCH**: Certificate subject CN=has.email does not match requested domains

## Mirror HTTPS Security

- **Total mirrors checked**: 5
- **Mirrors with HTTP to HTTPS redirects**: 0 (0%)
- **Mirrors without HTTP to HTTPS redirects**: 5 (100%)

| Mirror URL | HTTP Status | Security Issues |
|------------|-------------|-----------------|
| fedora.mirror.digitalpacific.com.au | 200 | Missing HSTS, Missing X-Content-Type-Options |
| ubuntu.mirror.digitalpacific.com.au | 200 | Missing HSTS, Missing X-Content-Type-Options |
| debian.mirror.digitalpacific.com.au | 200 | Missing HSTS, Missing X-Content-Type-Options |
| centos.mirror.digitalpacific.com.au | 200 | Redirects to fraudulent server |
| mirror.digitalpacific.com.au | 200 | Redirects to fraudulent server |

See detailed analysis in the [mirror HTTPS report](../reports/daily/mirror_https_report.md).

## Recommendations

1. **For Users**:
   - Switch to alternative DNS providers like Cloudflare (1.1.1.1) or Google (8.8.8.8)
   - Verify downloaded content using checksums or GPG signatures
   - Use HTTPS when accessing mirror sites, but be aware of certificate warnings

2. **For Superloop (ISP)**:
   - Investigate DNS cache poisoning in servers 119.40.106.35 and 119.40.106.36
   - Implement DNSSEC validation
   - Review DNS security measures and update TTL settings

3. **For Digital Pacific (Mirror Provider)**:
   - Implement HTTPS redirects on all mirrors
   - Add HSTS and X-Content-Type-Options headers
   - Monitor for server software changes (Apache vs nginx)