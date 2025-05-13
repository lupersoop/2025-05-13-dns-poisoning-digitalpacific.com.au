# Public Security Alert: DNS Poisoning Affecting Digital Pacific Linux Mirrors

## Security Alert: DNS Poisoning Affecting Popular Linux Mirrors

**Date:** May 12, 2025 (Updated: May 14, 2025)  
**Affected Services:** Digital Pacific Linux Mirrors (Fedora, Ubuntu, and potentially others)  
**Affected Users:** Primarily users accessing these mirrors through certain DNS resolvers  

## Overview

A DNS poisoning incident has been detected affecting Digital Pacific's Linux distribution mirrors. This issue redirects users to a potentially malicious server in Malaysia instead of the legitimate Digital Pacific mirrors.

**UPDATE (May 14, 2025)**: We are investigating reports that this incident may be related to a registrar-level compromise rather than an ISP DNS issue. We will update this advisory as more information becomes available.

## Technical Details

When using Superloop DNS servers (119.40.106.35, 119.40.106.36), the following redirection occurs:
- Legitimate destination: 101.0.120.90 (Digital Pacific)
- Malicious redirection: 111.90.150.116 (Malaysian server)

The malicious server presents an invalid certificate with "CN=has.email" that does not match the expected domain names.

## Immediate Actions for Users

If you are a Superloop customer and use their default DNS servers, you should:

1. **Change your DNS servers immediately** to one of these alternatives:
   - Cloudflare: 1.1.1.1, 1.0.0.1
   - Google: 8.8.8.8, 8.8.4.4
   - Quad9: 9.9.9.9, 149.112.112.112

2. **Verify the integrity** of any Linux packages or ISO files downloaded through Digital Pacific mirrors while using Superloop DNS servers since May 1, 2025.

3. **Use HTTPS where possible** when downloading software, and always verify checksums of downloaded files.

## How to Change DNS Servers

### Windows
1. Open Network & Internet settings
2. Click on Change adapter options
3. Right-click your connection and select Properties
4. Select Internet Protocol Version 4 (TCP/IPv4)
5. Click Properties
6. Select "Use the following DNS server addresses"
7. Enter your preferred DNS servers
8. Click OK to save

### macOS
1. Open System Preferences > Network
2. Select your active connection
3. Click Advanced
4. Select the DNS tab
5. Click + to add new DNS servers
6. Enter your preferred DNS servers
7. Click OK, then Apply

### Linux
Edit your /etc/resolv.conf file or use your distribution's network management tool.

## Status

This incident has been reported to Digital Pacific, Superloop, and relevant cybersecurity authorities. We will update this advisory as more information becomes available.

## Contact

If you believe you've been affected by this attack or have additional information, please contact:
- Digital Pacific: security@digitalpacific.com.au
- Australian Cyber Security Centre: https://www.cyber.gov.au/report

---

This alert may be updated as more information becomes available.

*This alert is part of the [DNS Poisoning Incident Report](../README.md)*