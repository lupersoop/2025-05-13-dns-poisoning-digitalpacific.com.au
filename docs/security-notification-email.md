# DNS Poisoning Incident Notification: Digital Pacific Mirrors via Superloop DNS

## Subject: [URGENT SECURITY ALERT] DNS Poisoning Attack Affecting Digital Pacific Mirrors

**To:** support@digitalpacific.com.au, abuse@superloop.com, noc@superloop.com, goc@superloop.com, security@digitalpacific.com.au, abuse@namecheap.com, abuse@shinjiru.com.my, info@cyber.gov.au
**CC:** security@fedoraproject.org, security@ubuntu.com, auscert@auscert.org.au, mycert@mycert.org.my
**Priority:** High

## Summary

I am writing to report a DNS poisoning attack affecting Digital Pacific mirror domains when resolved through Superloop DNS servers. This attack redirects legitimate mirror traffic to a suspicious server in Malaysia. The attack was discovered on May 11-12, 2025, and poses a significant security risk, especially to users attempting to download Linux distributions from Digital Pacific mirrors.

## Details of the Attack

The following domains are affected when using Superloop DNS servers (119.40.106.35, 119.40.106.36):
- fedora.mirror.digitalpacific.com.au
- ubuntu.mirror.digitalpacific.com.au
- centos.mirror.digitalpacific.com.au
- debian.mirror.digitalpacific.com.au

**Observed Behavior:**
1. Superloop DNS servers return a direct A record pointing to 111.90.150.116 (Malaysian IP)
2. Legitimate resolution should have a CNAME to mirror.digitalpacific.com.au and A record to 101.0.120.90
3. The attacker's DNS responses also falsely indicate nameservers "ns1.has.email" and "ns2.has.email" instead of the legitimate Cloudflare nameservers

**Malicious Infrastructure:**
- IP Address: 111.90.150.116
- Hostname: aspmxgoogle.has.email (mimicking Google mail servers)
- Certificate: CN=has.email (issued by Let's Encrypt)
- Hosting Provider: Shinjiru Technology Sdn Bhd, Malaysia
- ASN: 45839

**Evidence:**
- DNS queries to legitimate servers (Cloudflare 1.1.1.1) correctly resolve with CNAME + A records
- DNS queries to Superloop DNS servers return the malicious direct A record
- Direct queries to malicious IP show it's hosting a web server but no actual mirror content
- The malicious server appears to be running its own DNS server identifying itself as an authority for digitalpacific.com.au

## Recommended Actions

**For Digital Pacific:**
1. Verify your authoritative DNS records are correct (appears to be the case)
2. Update your mirrors website to use HTTPS instead of HTTP for all repository links
3. Consider adding DNSSEC to digitalpacific.com.au to prevent future poisoning attacks (currently unsigned)
4. Monitor your mirrors for unusual traffic patterns or access attempts
5. Issue a security alert to your users if appropriate

**For Superloop:**
1. Urgently investigate your DNS servers at 119.40.106.35 and 119.40.106.36 (NuSkope customer pool)
2. Check for unauthorized modifications to DNS cache or zone data
3. Implement DNSSEC validation if not already in place
4. Consider notifying affected customers
5. Review security of DNS infrastructure and implement additional safeguards

**For Australian Cyber Security Centre:**
1. Investigate the attack as it affects critical software distribution infrastructure
2. Consider alerting other Australian ISPs to check for similar poisoning
3. Monitor for additional compromises with similar patterns

**For Shinjiru Technology (Malaysia):**
1. Investigate potentially malicious activity on server 111.90.150.116
2. Review account associated with domains "has.email" and "aspmxgoogle.has.email"

**For NameCheap (has.email registrar):**
1. Review the registration details for has.email domain
2. Consider domain suspension due to malicious activity

## Impact

This DNS poisoning attack could potentially lead to:
1. Distribution of malware to users attempting to download Linux distributions
2. Interception of sensitive user data
3. Man-in-the-middle attacks against package managers
4. Compromise of systems that automatically update from these mirrors

## Evidence and Documentation

Complete details of the investigation, including all evidence, monitoring tools, and documentation related to this incident, are available in our GitHub repository:

**[https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au)**

The repository includes:
- DNS query logs showing the poisoning
- TLS certificate analysis
- Comparative resolution results from multiple DNS servers
- Analysis of the has.email domain and its infrastructure
- Daily monitoring reports and alerts
- Scripts for ongoing monitoring

## Contact Information

I can be reached at lupersoop@proton.me for any further details or evidence required.

Thank you for your prompt attention to this matter.

Sincerely,
Luper Soop

---

*This notification is part of the [DNS Poisoning Incident Report](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au)*