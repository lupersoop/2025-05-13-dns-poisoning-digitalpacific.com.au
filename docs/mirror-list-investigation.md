# Investigation: Digital Pacific Mirror List Security Analysis

## Aim

This investigation aimed to:

1. Determine if the Digital Pacific mirror list was affected by an observed DNS poisoning attack
2. Evaluate the security of HTTP vs HTTPS connections on the mirrors
3. Document the extent of redirections on listed mirror domains
4. Understand the potential attack vectors against users accessing these mirrors

## Method

1. **DNS Resolution Testing**:
   - Compared DNS resolution results between Superloop DNS servers and Cloudflare's services
   - Performed direct queries to the authoritative nameservers for digitalpacific.com.au
   - Tested various subdomains to determine the scope of the poisoning

2. **Mirror List Analysis**:
   - Retrieved the mirror list from https://mirror.digitalpacific.com.au/?page=mirrors
   - Extracted all HTTP URLs listed on the page
   - Tested HTTP to HTTPS redirections on major distribution mirrors
   - Examined certificate validation behavior

3. **Malicious Infrastructure Analysis**:
   - Attempted to connect to the suspicious IP (111.90.150.116) via HTTP and HTTPS
   - Analyzed the certificate presented by the suspicious server
   - Checked for rsync availability on the suspicious server
   - Attempted DNS queries directly to the suspicious server

4. **Script Creation**:
   - Developed a shell script to automate checking all mirror links
   - Tested for HTTP to HTTPS redirections
   - Recorded response codes and redirect URLs

## Results

### DNS Poisoning Confirmation

- **Poisoned Resolution**: When using Superloop DNS (119.40.106.35/36), queries for mirror subdomains resolve to 111.90.150.116 (Malaysia)
- **Legitimate Resolution**: When using Cloudflare DNS (1.1.1.1), queries properly resolve via CNAME to 101.0.120.90 (Digital Pacific)
- **NS Record Poisoning**: Superloop DNS returns fraudulent nameservers "ns1.has.email" and "ns2.has.email"

### Mirror List Security Findings

1. **No HTTPS by Default**:
   - All mirror links on the Digital Pacific mirror page use HTTP, not HTTPS
   - None of the major mirrors (Ubuntu, Fedora, Debian, CentOS, Arch Linux) automatically redirect to HTTPS
   - All tested mirrors return 200 OK responses over plain HTTP

2. **Suspicious Server Analysis**:
   - The Malaysian server (111.90.150.116) presents an invalid certificate for "has.email"
   - No legitimate mirror content was found on this server
   - rsync service is not available on the suspicious server
   - When directly queried as a DNS server, it responds as authoritative for digitalpacific.com.au

3. **Attack Impact**:
   - Users relying on Superloop DNS are directed to the suspicious server
   - Without HTTPS enforced, no certificate warnings appear when connecting over HTTP
   - This potentially allows for undetected content modification or malware distribution

### Security Recommendations

1. **For Digital Pacific**:
   - Update all mirror links to use HTTPS instead of HTTP
   - Implement automatic redirections from HTTP to HTTPS
   - Add DNSSEC to prevent future poisoning attacks
   - Consider implementing HSTS to enforce HTTPS usage

2. **For Mirrors Users**:
   - Always use HTTPS for downloading software, even when not provided as the default
   - Verify file checksums for all downloaded content
   - Use trusted DNS providers instead of ISP defaults

## Conclusion

The investigation confirmed an active DNS poisoning attack targeting Digital Pacific mirror users who rely on Superloop DNS servers. The attack is made significantly more effective by the lack of HTTPS enforcement on the mirrors. This combination creates a highly vulnerable scenario where users could unknowingly download compromised content without any browser security warnings.

The absence of automatic HTTP to HTTPS redirections across all tested mirrors represents a significant security gap that should be addressed promptly to protect users from both this specific attack and potential future threats.

## Related Documents

- [Return to main report](../README.md)
- [Notification templates](../docs/)
- [Check redirect script](../scripts/check_mirror_redirects.sh)