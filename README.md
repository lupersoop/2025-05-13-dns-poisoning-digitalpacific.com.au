# DNS Poisoning Incident Report: Superloop DNS Servers

## GitHub Repository

All materials, evidence, and monitoring tools related to this incident are available in this GitHub repository:
https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au

## Summary

This report documents evidence of a sophisticated DNS poisoning attack affecting [Superloop](./docs/superloop.md) DNS servers (119.40.106.35, 119.40.106.36) discovered on May 11-12, 2025. Superloop's DNS resolvers are returning fraudulent nameservers (`ns1.has.email` and `ns2.has.email`) from the malicious [`has.email`](./docs/has-email-investigation.md) domain for the `digitalpacific.com.au` domain, which hosts popular open source project mirrors including Fedora and Ubuntu.

When users query these poisoned DNS servers for mirror subdomains like `fedora.mirror.digitalpacific.com.au`, the fraudulent nameservers respond with IP address `111.90.150.116` (a server in Malaysia) instead of the legitimate `101.0.120.90`. The malicious server responds to both HTTP and HTTPS requests, presenting an invalid certificate with CN=has.email for HTTPS connections.

This attack is particularly effective because [Digital Pacific's mirrors page](./docs/mirror-list-investigation.md) links to all projects using HTTP (not HTTPS) URLs, making them perfect targets for poisoning as browsers won't show certificate warnings for non-HTTPS connections.

## Timeline

- May 11-12, 2025: DNS poisoning discovered and documented

## Evidence of DNS Poisoning

### 1. Poisoned NS Records for digitalpacific.com.au

When querying Superloop DNS servers for the nameservers responsible for digitalpacific.com.au:

| DNS Server                                       | Query                    | Nameservers Returned                                                                                 |
| ------------------------------------------------ | ------------------------ | ---------------------------------------------------------------------------------------------------- |
| [Superloop](./docs/superloop.md) (119.40.106.35) | NS digitalpacific.com.au | [ns1.has.email, ns2.has.email](./docs/has-email-investigation.md)                                    |
| Default/Cloudflare (1.1.1.1)                     | NS digitalpacific.com.au | ns1.digitalpacific.com.au, ns2.digitalpacific.com.au, ns3.digitalpacific.com, ns4.digitalpacific.com |

### 2. Divergent DNS Resolution Results

| DNS Server                                          | Domain                              | Result Type      | IP Address     | Notes                                            |
| --------------------------------------------------- | ----------------------------------- | ---------------- | -------------- | ------------------------------------------------ |
| [Superloop](./docs/superloop.md) (119.40.106.35/36) | ubuntu.mirror.digitalpacific.com.au | A Record         | 111.90.150.116 | Suspicious direct A record                       |
| Cloudflare (1.1.1.1)                                | ubuntu.mirror.digitalpacific.com.au | CNAME + A Record | 101.0.120.90   | Legitimate CNAME to mirror.digitalpacific.com.au |
| Local Resolver (127.0.0.53)                         | fedora.mirror.digitalpacific.com.au | A Record         | 111.90.150.116 | Poisoned result from ISP                         |
| Cloudflare NS (162.159.25.173)                      | fedora.mirror.digitalpacific.com.au | CNAME + A Record | 101.0.120.90   | Legitimate CNAME to mirror.digitalpacific.com.au |

### 3. Suspicious TLS Certificate

When connecting to the IP address returned by Superloop DNS (111.90.150.116):

```shell
curl https://fedora.mirror.digitalpacific.com.au -vvv
```

- TLS certificate details:
  - Subject: CN=has.email
  - Valid: April 17, 2025 - July 16, 2025
  - Certificate does NOT match domain fedora.mirror.digitalpacific.com.au
  - Connection fails with error: "SSL: no alternative certificate subject name matches target host name"

### 4. Authoritative DNS Configuration

- The authoritative nameservers for digitalpacific.com.au are hosted by Cloudflare (162.159.25.173, 162.159.24.135)
- Querying the Cloudflare nameserver directly provides the legitimate resolution:
  - fedora.mirror.digitalpacific.com.au → CNAME mirror.digitalpacific.com.au → A 101.0.120.90

### 5. Malicious Server Information

The poisoned IP address (111.90.150.116) associated with the [`has.email`](./docs/has-email-investigation.md) domain has been identified with the following details:

| Data Type   | Information                      |
| ----------- | -------------------------------- |
| IP Address  | 111.90.150.116                   |
| Hostname    | aspmxgoogle.has.email            |
| ISP         | Shinjiru Technology Sdn Bhd      |
| ISP Domain  | SHINJIRU.COM.MY                  |
| ISP Type    | Data Center/Web Hosting/Transit  |
| ASN         | 45839                            |
| CIDR        | 111.90.144.0/21                  |
| Country     | Malaysia (MY)                    |
| Region      | Wilayah Persekutuan Kuala Lumpur |
| City        | Kuala Lumpur                     |
| Time Zone   | +08:00                           |
| Coordinates | 3.141301, 101.686621             |

Source: [Vedbex GeoIP Lookup](https://www.vedbex.com/geoip/111.90.150.116)

The hostname "aspmxgoogle.has.email" appears designed to mimic legitimate Google mail servers (typically named aspmx.l.google.com), while the certificate's common name "has.email" further suggests an attempt to appear legitimate. For a complete analysis of this malicious domain, see the [has.email investigation report](./docs/has-email-investigation.md).

## Technical Analysis

1. **Poisoning Mechanism**: [Superloop](./docs/superloop.md) DNS servers are returning fraudulent nameservers (`ns1.has.email` and `ns2.has.email`) for the domain `digitalpacific.com.au`. These malicious nameservers then respond to queries for the mirror subdomains with direct A records pointing to 111.90.150.116.

2. **HTTP Exploitation**: The attack specifically targets [Digital Pacific's mirror infrastructure](./docs/mirror-list-investigation.md) which links to all mirrors using HTTP (not HTTPS). When users access these mirrors via HTTP, there are no certificate warnings despite connecting to a malicious server.

3. **Impact**: Users of Superloop's DNS servers attempting to download Linux distributions or open source packages from any digitalpacific.com.au mirror are directed to a suspicious Malaysian server potentially serving modified content.

4. **Verification**: When bypassing Superloop DNS and querying the authoritative Cloudflare nameservers directly, the correct nameservers and CNAME/A records are returned.

5. **Attack Infrastructure**: The [`has.email`](./docs/has-email-investigation.md) domain and server infrastructure appear specifically designed for this attack, with both nameservers pointing to the same IP address (111.90.150.116) and a certificate using the same domain name.

## Recommendations

1. **For [Superloop](./docs/superloop.md)**: Investigate potential DNS cache poisoning or server compromise in DNS infrastructure at 119.40.106.35 and 119.40.106.36.

2. **For Users**: Temporarily switch to alternative DNS servers such as:

   - Cloudflare: 1.1.1.1, 1.0.0.1
   - Google: 8.8.8.8, 8.8.4.4

3. **For Digital Pacific**: Verify DNS records are correct at the authoritative level (appears to be the case) and consider implementing HTTPS for all mirror links.

4. **For Authorities**: Investigate the suspicious server at 111.90.150.116, registered to Shinjiru Technology in Malaysia, and the entity behind the [`has.email`](./docs/has-email-investigation.md) domain and certificate.

## Attachments and Raw Data

Complete logs and DNS query results have been preserved and are available for forensic analysis in the [data/](data/) directory. Daily reports are centralized in the [reports/](reports/) directory for easier access.

**Key Evidence Files:**

- [Curl attempt to fedora mirror](data/misc/curl-fedora.mirror.digitalpacific.com.au.txt) - Shows certificate errors
- [Superloop DNS tests](data/misc/superloop-dns-poisoning.txt) - Poisoned responses from Superloop DNS
- [DNS query to legitimate nameserver](data/misc/dig-fedora.mirror.digitalpacific.com.au.txt) - Correct response

**Daily Monitoring Reports:**

Reports from the monitoring system are available in the [reports/daily/](./reports/daily/) directory, with incident-specific reports in [reports/incidents/](reports/incidents/).

## Extended Analysis

Additional investigation has been conducted to assess the security implications of the Digital Pacific mirror infrastructure and the impact of this attack:

- [Mirror List Security Investigation](./docs/mirror-list-investigation.md) - Analysis of HTTP vs HTTPS usage across all Digital Pacific mirrors
- [has.email Investigation](./docs/has-email-investigation.md) - Detailed analysis of the malicious has.email domain and nameservers
- [Superloop Company Profile](./docs/superloop.md) - Background information on Superloop's business, customer base, and security claims
- [Contact Information](./docs/contact-information.md) - Comprehensive contact details for all entities involved in this incident
- [Safe Disclosure and Rewards](./docs/safe-disclosure-and-rewards.md) - Guidelines for safely reporting this vulnerability
- [Scheduled Monitoring](./docs/scheduled-monitoring.md) - System for tracking DNS poisoning patterns and collecting evidence

## Tools and Monitoring

To monitor this DNS poisoning attack, we have created a comprehensive monitoring system:

- Full-featured DNS monitoring with HTTP security, certificate validation, and attack detection
  - Usage: `make run` to run the monitoring system
  - Features: DNS analysis, certificate validation, content verification, mirror HTTP security checks
  - Results are available in the [reports/daily/](reports/daily/) directory

## Notification Templates

- [Security Notification Email](docs/security-notification-email.md) - Template for notifying stakeholders
- [Public Security Alert](docs/public-security-alert.md) - Template for public advisory

## Additional Information

- **Investigation Date**: 2025-05-12
- **Investigator's Network**: 100.101.56.130/20
- **Investigator Contact**: lupersoop@proton.me
- **Repository**: https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au
- **Repository Last Updated**: May 13, 2025
