# DNS Monitoring Reports

This directory contains reports generated by the DNS monitoring system, organized for easy access and review.

## Directory Structure

- `/daily` - Daily monitoring summary reports (symlinks to the reports in data directory)
- `/incidents` - Special reports for detected DNS poisoning incidents
- `/templates` - Templates for generating reports

## Usage

Daily reports are automatically generated by the DNS monitoring system and symlinked here for convenience. You can access the most recent report with:

```bash
ls -lt reports/daily | head -2
```

## Report Types

### Daily Summary Reports

Daily summary reports contain:
- List of monitored domains
- DNS poisoning detection results
- HTTPS redirect status for mirrors
- Certificate validation results
- Summary statistics

### Incident Reports

When DNS poisoning is detected, detailed incident reports are generated containing:
- Affected domains and nameservers
- Timeline of the incident
- Evidence collected
- Technical analysis
- Recommended actions

## Related Documentation

- [DNS Monitor Documentation](../docs/user/usage.md)
- [Report Format Specification](../docs/developer/report-format.md)