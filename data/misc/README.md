# DNS Poisoning Investigation Evidence

This directory contains the raw evidence collected during the investigation of DNS poisoning affecting Superloop DNS servers and Digital Pacific mirrors.

## DNS Query Results

- [dig-fedora.mirror.digitalpacific.com.au.txt](dig-fedora.mirror.digitalpacific.com.au.txt) - DNS query to local resolver (showing poisoned result)
- [dig-fedora.mirror.digitalpacific.com.au-at-162.159.25.173](dig-fedora.mirror.digitalpacific.com.au-at-162.159.25.173) - DNS query to authoritative Cloudflare nameserver (showing legitimate result)
- [dig-ns1.digitalpacific.com.au.txt](dig-ns1.digitalpacific.com.au.txt) - DNS query for nameserver records
- [dig-thepiratebay.org](dig-thepiratebay.org) - Reference comparison query

## Connection Tests

- [curl-fedora.mirror.digitalpacific.com.au.txt](curl-fedora.mirror.digitalpacific.com.au.txt) - HTTPS connection attempt to the fedora mirror showing certificate errors
- [superloop-dns-poisoning.txt](superloop-dns-poisoning.txt) - Testing Superloop DNS servers directly

## Network Information

- [ifconfig](ifconfig) - Local network configuration at time of testing

## Contact Information

- [superloop-contact-info.md](superloop-contact-info.md) - WHOIS information for Superloop DNS servers
- [digitalpacific-contact-info.md](digitalpacific-contact-info.md) - WHOIS information for Digital Pacific