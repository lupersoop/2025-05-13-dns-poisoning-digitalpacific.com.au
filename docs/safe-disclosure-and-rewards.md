# Safe Disclosure and Potential Rewards

This document outlines approaches for safely disclosing the DNS poisoning attack affecting Digital Pacific mirrors via Superloop DNS while minimizing personal risk. It also explores potential avenues for recognition or compensation for security research.

## Safe Disclosure Methods

### Anonymous Disclosure Options

1. **Tor Browser + Anonymous Email**
   - Install the Tor Browser (https://www.torproject.org/)
   - Create an anonymous email account (ProtonMail or Tutanota) through Tor
   - Communicate using this email without revealing personal information
   - Access all disclosure platforms through Tor to mask your IP address
   - Use a different Tor circuit for each communication platform (click the padlock icon → New Tor Circuit for this Site)
   - Never access personal accounts or identifiable services during the same session

2. **SecureDrop**
   - Some news organizations offer SecureDrop for anonymous tips
   - ABC News Australia: https://www.abc.net.au/news/securedrop/ 
   - The Guardian: https://www.theguardian.com/securedrop
   - Access only via Tor Browser for maximum anonymity

3. **Anonymous Whistleblower Platforms**
   - Your Call: https://whistleblowing.com.au/ (Australian whistleblowing service)
   - Provides methodology for detailed anonymous disclosures
   - Allows for two-way anonymous communication

4. **Virtual Private Disclosure**
   - Use a new device purchased with cash (not linked to you)
   - Connect only via public Wi-Fi (libraries, cafes) at a distance from your home/work
   - Use a VPN service that doesn't keep logs
   - Create single-use email addresses for communications
   - Consider using Tails OS (https://tails.boum.org/) - an amnesic operating system that leaves no digital footprint
   - Never link the device to personal accounts, cloud services, or existing email addresses

### Disclosure Recipients and Order

For maximum impact with minimal risk, consider this disclosure sequence:

1. **Australian Cyber Security Centre (ACSC)**
   - Report via their online form: https://www.cyber.gov.au/report
   - Provides built-in protection through the limited use obligation
   - Focus on the technical details without personal identification

2. **Digital Pacific Security Team**
   - Contact via security@digitalpacific.com.au
   - They have direct ability to fix their mirror infrastructure

3. **Superloop Security Team**
   - Contact via security@superloop.com
   - Focus on the DNS poisoning aspect affecting their infrastructure

4. **Media Disclosure (if no action after reasonable time)**
   - Technology journalists at ABC, The Guardian, or IT News
   - Use SecureDrop where available
   - Provide complete documentation while maintaining anonymity

### Information to Include in Disclosure

1. **Technical Evidence**
   - DNS query results showing the poisoning
   - IP addresses and nameserver details
   - Timeline of discovery
   - Impact assessment (which mirrors are affected)

2. **Urgency Factors**
   - Highlight the malicious Malaysian server (111.90.150.116)
   - Emphasize the risk to users downloading software
   - Note the targeting of HTTP connections to avoid certificate warnings

3. **Mitigation Recommendations**
   - Immediate steps for affected users (changing DNS servers)
   - Infrastructure fixes for Digital Pacific (HTTPS implementation)
   - Security improvements for Superloop (DNS security measures)

## Legal Protections

### Australian Whistleblower Protections

The Corporations Act provides protections for whistleblowers disclosing serious issues:

1. **Identity Protection**
   - It's illegal for recipients to reveal your identity without consent
   - Anonymous disclosures are legally protected
   - Companies cannot enforce non-disclosure agreements to prevent reporting
   - Protection applies even if you don't explicitly state you're making a "protected disclosure"

2. **Protection Against Retaliation**
   - Legal safeguards against dismissal, demotion, harassment
   - Protection from legal action, including lawsuits
   - Criminal penalties for those who cause detriment to whistleblowers

3. **Public Interest Disclosure Act**
   - Provides additional protections for public sector related disclosures
   - Ensures proper investigation of valid concerns

### Limitations and Considerations

1. **National Security Concerns**
   - Disclosures affecting national security have more restrictions
   - Unauthorized disclosure of Commonwealth information can be a federal crime
   - The DNS poisoning may touch on national infrastructure security

2. **Documentation Practices**
   - Maintain detailed records of all communications
   - Save evidence of the vulnerability and its discovery
   - Document any responses from organizations

## Potential Rewards and Recognition

### Bug Bounty Programs

1. **Private Sector Programs**
   - **NAB Bug Bounty**: NAB launched Australia's first banking bug bounty program in 2021 through Bugcrowd
   - **AustralianSuper Bug Bounty**: Available through Bugcrowd platform

2. **International Programs That May Apply**
   - HackerOne platform hosts bounties for many organizations
   - Bugcrowd maintains a comprehensive list of international programs
   - Some programs accept vulnerabilities in third-party services used by their customers

3. **Australian Government Position**
   - The Australian federal government does not currently operate a bug bounty program
   - The Australian Signals Directorate (ASD) has stated they have "never considered" implementing such a program
   - No financial rewards are typically offered for reporting vulnerabilities to government entities

### Recognition Options

1. **Hall of Fame / CVE Credit**
   - Request acknowledgment in public disclosure statements
   - Apply for a CVE (Common Vulnerabilities and Exposures) identifier
   - Potential recognition in security advisory publications

2. **Responsible Disclosure Recognition**
   - Some organizations publicly acknowledge security researchers
   - Digital Pacific or Superloop may offer recognition
   - Could be valuable for professional portfolio (if anonymity not required)

3. **Media Coverage**
   - Opportunities for anonymous expert quotes
   - Technical documentation may be published (with attribution only if desired)
   - Potential for case study in security publications

### Alternative Compensation Approaches

1. **Professional Services**
   - Offer security consulting services to affected organizations
   - Conduct a formal security assessment (paid engagement)
   - Develop remediation plans or security training

2. **Academic/Research Recognition**
   - Submit findings to security conferences (anonymously if needed)
   - Develop academic papers on the DNS poisoning technique
   - Contribute to security education resources

3. **Security Community Support**
   - Some security communities offer grants or awards for important research
   - Platforms like Patreon allow for community support of security research
   - Open source project contributions related to DNS security

## Ethical Considerations

1. **Harm Reduction**
   - Primary focus should be protecting users from malicious actors
   - Balance disclosure timing with risk to the public
   - Consider organizations' reasonable time to respond

2. **Proportional Disclosure**
   - Start with direct, private disclosure to affected parties
   - Escalate only if necessary for public protection
   - Maintain professionalism in all communications

3. **Long-term Impact**
   - Consider how your actions might affect future security research
   - Responsible disclosure helps maintain an environment where security research is valued
   - Avoid actions that could damage the relationship between researchers and organizations

## Conclusion

The DNS poisoning attack affecting Digital Pacific mirrors via Superloop DNS represents a significant security threat to Australian internet users. Disclosing this information safely while minimizing personal risk requires careful planning and technical precautions.

While Australia lacks a formal government bug bounty program, there are potential avenues for recognition or compensation through private sector programs, professional services, or community support. The primary motivation should remain the protection of users and infrastructure from malicious exploitation.

For any disclosure approach, maintaining strong operational security practices is essential to protect your identity if anonymity is desired. Using anonymous communication channels, avoiding personal identifiers, and carefully considering the timing and recipients of your disclosure will help minimize personal risk while maximizing the positive impact of your security research.

---

*Note: This document is for informational purposes only and does not constitute legal advice. Laws regarding whistleblower protection and vulnerability disclosure vary by jurisdiction and change over time. Consult with a qualified legal professional before making any decisions regarding vulnerability disclosure that might have legal implications.*