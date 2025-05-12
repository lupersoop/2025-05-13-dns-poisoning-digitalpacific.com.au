# has.email Domain Investigation

## Overview

As part of the investigation into the DNS poisoning attack affecting Digital Pacific mirrors, we examined the `has.email` domain, which appeared in the poisoned DNS responses. The fraudulent nameservers (`ns1.has.email` and `ns2.has.email`) were being returned by Superloop's DNS servers for `digitalpacific.com.au` instead of the legitimate nameservers.

## Domain Information

### Basic Information

- **Domain Name**: has.email
- **Creation Date**: August 1, 2024 (approximately 9 months old)
- **Last Updated**: May 6, 2025 (very recent, just days before the attack was discovered)
- **Expiration Date**: August 1, 2025
- **DNSSEC**: Unsigned (vulnerable to DNS spoofing)

### DNS Records

| Record Type | Name | Value | TTL |
|-------------|------|-------|-----|
| A | has.email | 111.90.150.116 | 14400 |
| MX | has.email | 0 has.email | 14400 |
| NS | has.email | ns1.has.email | 86400 |
| NS | has.email | ns2.has.email | 86400 |
| A | ns1.has.email | 111.90.150.116 | 14400 |
| A | ns2.has.email | 111.90.150.116 | 14400 |

### Nameserver Analysis

The domain uses two nameservers, `ns1.has.email` and `ns2.has.email`, both of which resolve to the same IP address (111.90.150.116). This is unusual for legitimate domains, which typically use multiple IP addresses for DNS redundancy. Having both nameservers point to the same IP address defeats the purpose of having multiple nameservers for high availability.

## DNS Resolution Capabilities

### Domain Resolution Tests

When querying the `ns1.has.email` nameserver (111.90.150.116) directly for various digitalpacific.com.au subdomains, we observed the following resolution patterns:

#### Basic Domains
| Domain | Resolves | IP Address(es) | Notes |
|--------|----------|----------------|-------|
| digitalpacific.com.au | ✅ | 111.90.150.116, 101.0.96.154 | Multiple A records |
| www.digitalpacific.com.au | ✅ | CNAME → digitalpacific.com.au | CNAME to parent domain |

#### Mirror Subdomains
| Domain | Resolves | IP Address(es) | Notes |
|--------|----------|----------------|-------|
| fedora.mirror.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |
| ubuntu.mirror.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |

#### Infrastructure Subdomains
| Domain | Resolves | IP Address(es) | Notes |
|--------|----------|----------------|-------|
| ns1.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |
| ns2.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |
| mail.digitalpacific.com.au | ✅ | CNAME → digitalpacific.com.au | CNAME to parent domain |
| ftp.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |
| webmail.digitalpacific.com.au | ✅ | 111.90.150.116 | Points to has.email IP |

### Authority Claims

The has.email nameserver claims to be the authoritative source for digitalpacific.com.au:

#### SOA (Start of Authority) Record
```
digitalpacific.com.au. 86400 IN SOA ns1.has.email. root.aspmxgoogle.has.email. 2025050615 3600 1800 1209600 86400
```

This shows that has.email is claiming to be the Start of Authority for the digitalpacific.com.au domain.

#### NS Records
```
digitalpacific.com.au. 86400 IN NS ns1.has.email.
digitalpacific.com.au. 86400 IN NS ns2.has.email.
```

The nameserver is presenting itself as the authoritative nameserver for digitalpacific.com.au.

#### Additional Records
```
digitalpacific.com.au. 14400 IN TXT "atlassian-domain-verification=3saWh0dKVBf3qTK1BnkSR1upUaTPtAzJuLZthH30PVG/jyGC33k/6CIRv8ISM7FH"
digitalpacific.com.au. 14400 IN TXT "v=spf1 ip4:111.90.150.116 +a +mx ~all"
digitalpacific.com.au. 14400 IN MX 0 digitalpacific.com.au.
```

The server also provides TXT and MX records for the domain, further establishing its comprehensive impersonation of legitimate DNS services.

This comprehensive setup demonstrates that the attack was not just simple DNS poisoning but a deliberate attempt to establish has.email as the authoritative DNS provider for digitalpacific.com.au.

### Conclusion on DNS Capabilities

The has.email nameserver (111.90.150.116) demonstrates the following capabilities:

1. Successfully resolving all tested digitalpacific.com.au subdomains
2. Claiming to be the authoritative nameserver for the domain (via NS records)
3. Claiming to be the Start of Authority for the domain
4. Directing most subdomains to resolve to its own IP address (111.90.150.116)
5. Providing multiple record types (A, CNAME, MX, TXT, SOA, NS)

This suggests a comprehensive DNS poisoning attack where has.email has positioned itself as the authoritative DNS provider for digitalpacific.com.au, redirecting legitimate requests for services (particularly mirror services) to its own servers.

## Registrar Information

- **Registrar**: NameCheap, Inc.
- **Registrar IANA ID**: 1068
- **Registrar Abuse Contact**: abuse@namecheap.com
- **Domain Status**: clientTransferProhibited

### Registrant Information

The domain is registered using a privacy service:

- **Registrant Organization**: Privacy service provided by Withheld for Privacy ehf
- **Registrant Country**: IS (Iceland)

## IP Address Information (111.90.150.116)

The IP address used by both the domain and its nameservers is associated with:

- **ISP/Host**: Shinjiru Technology Sdn Bhd
- **Location**: Kuala Lumpur, Malaysia
- **Netblock**: 111.90.128.0 - 111.90.159.255
- **AS Numbers**: AS19324, AS45839
- **Abuse Contact**: abuse@shinjiru.com.my

### Hosting Provider Background

Shinjiru is a Malaysian hosting provider known for:

- Offering "offshore hosting" services
- Marketing "bullet-proof hosting" solutions
- Having a reputation for hosting content that might be rejected by more mainstream hosting providers
- Advertising high anonymity and privacy for website owners

## Connection to DNS Poisoning Attack

This domain and its associated IP address are central to the DNS poisoning attack:

1. The poisoned Superloop DNS servers return `ns1.has.email` and `ns2.has.email` as the authoritative nameservers for `digitalpacific.com.au`
2. Both these nameservers point to 111.90.150.116
3. When DNS queries for mirror subdomains like `fedora.mirror.digitalpacific.com.au` are made to these fraudulent nameservers, they return 111.90.150.116 as the A record
4. This effectively redirects all mirror traffic to this Malaysian server
5. The same IP hosts the HTTPS server presenting an invalid certificate for "has.email"

## Security Implications

The configuration of this domain exhibits several red flags:

1. **Single-point design**: Both nameservers resolve to the same IP, indicating this is not set up for legitimate high-availability DNS hosting
2. **Recent domain activity**: The domain was updated just days before the attack was discovered
3. **Privacy-protected registration**: The actual owner is hidden behind a privacy service
4. **Bullet-proof hosting**: The choice of hosting provider suggests an attempt to avoid takedown requests
5. **Self-referential setup**: The domain's nameservers are within the domain itself, creating a circular dependency
6. **Same IP for all services**: The same IP is used for the domain, nameservers, and mail service

## Conclusion

The `has.email` domain appears to have been specifically created and configured for the DNS poisoning attack targeting Digital Pacific mirrors. Its configuration, hosting choice, and recent activity all suggest malicious intent rather than legitimate use.

This domain should be reported to:

1. NameCheap (the registrar) at abuse@namecheap.com
2. Shinjiru Technology (the hosting provider) at abuse@shinjiru.com.my
3. Relevant cybersecurity authorities

## References

- [DNS Poisoning Incident Report](../README.md)
- [Mirror List Investigation](./mirror-list-investigation.md)
- [Public Security Alert](./public-security-alert.md)