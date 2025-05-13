# Domain Registration Records Modification Investigation

## Overview

On May 14, 2025, Superloop responded to our security notification email with important feedback regarding the DNS poisoning incident affecting digitalpacific.com.au domains. Their investigation suggested that the root cause was **unauthorized changes to domain registration records at the registrar level** involving TPP Wholesale, rather than an issue with Superloop's DNS resolvers.

After reviewing historical WHOIS data, we have **confirmed** that Superloop's explanation is correct. This document presents the evidence and analysis of these unauthorized nameserver changes.

## Superloop's Response

Superloop provided the following key points:

1. The DNS issues were due to unauthorized modifications of domain registration records through TPP Wholesale rather than Superloop DNS resolver issues
2. This changes the attribution of responsibility from Superloop to the domain registration infrastructure
3. They suggested we review historical WHOIS data as evidence of the unauthorized changes
4. They recommended updating our repository to reflect this explanation

## Definitive Evidence of Unauthorized Nameserver Changes

After accessing historical WHOIS data from WhoisFreaks.com, we have obtained definitive evidence confirming Superloop's explanation:

| Date           | Nameservers                                                                                          | Update Date    | Status                |
| -------------- | ---------------------------------------------------------------------------------------------------- | -------------- | --------------------- |
| 2025-05-13     | ns2.digitalpacific.com.au, ns1.digitalpacific.com.au, ns4.digitalpacific.com, ns3.digitalpacific.com | 2025-05-07     | serverRenewProhibited |
| **2025-05-06** | **ns2.has.email, ns1.has.email**                                                                     | **2025-05-06** | serverRenewProhibited |
| 2024-09-24     | ns2.digitalpacific.com.au, ns1.digitalpacific.com.au, ns4.digitalpacific.com, ns3.digitalpacific.com | 2024-08-31     | serverRenewProhibited |

The WHOIS history clearly shows that on May 6, 2025, the nameservers for digitalpacific.com.au were explicitly changed to the malicious ns1.has.email and ns2.has.email servers. The next day, May 7, 2025, the nameservers were reverted back to the legitimate ones.

This confirms that the attack involved unauthorized modification of domain registration records, not simply DNS cache poisoning at the resolver level.

## Revised Attack Vector Analysis

Based on the historical WHOIS data, we can reconstruct the attack sequence:

1. **Unauthorized Access (On or before May 6, 2025)**:

   - Attackers gained the ability to change domain registration records. This could have happened through:
     - Domain management account compromise
     - Social engineering of registrar staff
     - Exploitation of a vulnerability in registrar systems
     - Insider action
   - Without internal investigation data from the registrar, we cannot determine which specific vector was used

2. **Nameserver Hijacking (May 6, 2025)**:

   - The domain's authoritative nameservers were changed to ns1.has.email and ns2.has.email
   - These malicious nameservers were configured to respond to queries for Digital Pacific's mirror subdomains with the attacker's IP address (111.90.150.116)

3. **Brief Attack Window (24 hours)**:

   - The nameservers were only changed for approximately 24 hours
   - This was sufficient to poison DNS caches across various resolvers on the internet
   - The short window may have been strategic to avoid detection or may indicate rapid response by Digital Pacific/the registrar

4. **Recovery/Reversion (May 7, 2025)**:

   - The nameserver records were changed back to the legitimate servers
   - This could have been initiated by Digital Pacific, the registrar, or automated security systems

5. **Lingering Effects (May 11-12, 2025 and beyond)**:
   - Despite the nameserver reversion, DNS poisoning effects persisted for several days due to caching
   - Different DNS resolvers (including Superloop's) continued serving the poisoned data until their caches expired
   - This explains why the effects were observed several days after the actual record changes were reverted

## Connection to TPP Wholesale

The connection to TPP Wholesale is significant:

1. TPP Wholesale is an Australian wholesale domain registrar and web hosting provider
2. Domain Directors Pty Ltd (Instra), the current registrar for digitalpacific.com.au, works with TPP Wholesale
3. In 2020, TPP Wholesale consolidated all .au domain names under Domain Directors (Instra)
4. This relationship creates a potential attack surface that could affect domains managed through this registrar chain

## Revised Impact Assessment

This confirmed unauthorized modification of domain registration records has several important implications:

1. **Broader Scope**: This type of attack could potentially affect other domains registered through the same registrar
2. **Sophisticated Attack**: This represents a more targeted and sophisticated attack than DNS cache poisoning
3. **Accurate Attribution**: Superloop's DNS resolvers were correctly reflecting the data they received based on the modified nameserver records
4. **Persistence Through Caching**: The effects persisted long after the actual record changes were reverted due to DNS caching

## Recommendations

Based on our findings:

1. **For Digital Pacific and Other Domain Owners**:

   - Implement registry locks when available to prevent unauthorized domain changes
   - Enable multi-factor authentication for domain registration accounts
   - Monitor nameserver changes closely
   - Consider using DNSSEC to prevent similar attacks in the future

2. **For Registrars (Domain Directors/TPP Wholesale)**:

   - Investigate how these unauthorized changes occurred
   - Implement additional security measures for nameserver changes
   - Review account security policies
   - Consider implementing automated monitoring for suspicious nameserver changes

3. **For DNS Operators**:

   - Consider implementing shorter TTLs for nameserver records to limit the persistence of attacks
   - Monitor for sudden nameserver changes, especially to unfamiliar domains

4. **For Australian Cyber Security Centre**:
   - Investigate the unauthorized domain record changes
   - Determine if other domains were affected
   - Issue broader advisories to Australian registrars

## Conclusion

The historical WHOIS data provides conclusive evidence that this incident stemmed from unauthorized modification of domain registration records rather than an issue with Superloop's DNS resolvers. The unauthorized change of nameservers to ns1.has.email and ns2.has.email on May 6, 2025, followed by reversion on May 7, 2025, created a brief but effective attack window that resulted in widespread DNS poisoning effects.

Superloop's explanation has been fully validated, and attribution for this incident should focus on the security of domain registration systems rather than DNS resolvers. However, without internal investigation by the registrar, we cannot determine the specific method used to make these unauthorized changes (account compromise, social engineering, system vulnerability, or insider action).

For a detailed analysis of the historical WHOIS data and its implications, see [WHOIS Historical Analysis](./whois-historical-analysis.md).

