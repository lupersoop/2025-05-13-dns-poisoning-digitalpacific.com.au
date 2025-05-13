# Response to Superloop

## Subject: RE: [URGENT SECURITY ALERT] DNS Poisoning Attack Affecting Digital Pacific Mirrors - CONFIRMED Unauthorized Domain Record Changes

Dear Superloop,

Thank you for your prompt response to our security notification regarding the DNS issues affecting Digital Pacific mirrors. Your insight about the unauthorized changes to domain registration records involving TPP Wholesale was absolutely correct, and I appreciate you steering our investigation in the right direction.

Following your recommendation, I accessed historical WHOIS data from WhoisFreaks.com and found **definitive evidence confirming your assessment**. The data clearly shows:

- On May 6, 2025, the nameservers for digitalpacific.com.au were changed to ns1.has.email and ns2.has.email
- On May 7, 2025, they were reverted back to the legitimate nameservers
- This brief window of unauthorized changes was sufficient to poison DNS caches, with effects persisting until our observation on May 11-12

This confirms beyond doubt that the incident stemmed from unauthorized modification of domain registration records rather than any issue with Superloop's DNS resolvers. Your team's analysis was spot-on, and I've completely revised our documentation to reflect this finding.

I've taken the following actions:

1. Created detailed analysis documents:

   - [WHOIS Historical Analysis](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au/blob/master/docs/whois-historical-analysis.md) - Shows the direct evidence of nameserver changes
   - [Domain Registration Records Modification Investigation](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au/blob/master/docs/registrar-compromise-investigation.md) - Analysis of the attack vector and implications

2. Updated the repository README with a clear statement confirming your explanation

3. Revised the timeline to accurately reflect the sequence of events, beginning with the May 6 nameserver change

4. Added specific recommendations for domain registrars, registry operators, and domain owners

I would like to sincerely apologize for the incorrect initial attribution in our report. While the DNS poisoning effects we observed were accurate, we failed to trace them back to their true source. Your insight was invaluable in establishing the correct attack vector.

If you have any additional information about this incident or suggestions for further investigation, I would welcome your continued collaboration. I'm particularly interested in whether your team has identified any other domains potentially affected by these unauthorized domain record changes.

Thank you again for your critical feedback which has significantly improved the accuracy of our security incident report. Your expertise has been instrumental in correctly attributing this sophisticated attack.

Sincerely,

Luper Soop
lupersoop@proton.me

---

**Updated Repository Resources:**

- [WHOIS Historical Analysis](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au/blob/master/docs/whois-historical-analysis.md) - Historical WHOIS evidence
- [Domain Registration Records Modification Investigation](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au/blob/master/docs/registrar-compromise-investigation.md) - Complete analysis
- [Updated README](https://github.com/lupersoop/2025-05-13-dns-poisoning-digitalpacific.com.au/blob/master/README.md) - Revised with confirmed findings

