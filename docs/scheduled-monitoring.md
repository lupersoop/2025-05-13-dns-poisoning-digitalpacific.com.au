# Scheduled DNS Monitoring

This document provides instructions for setting up automated, scheduled DNS monitoring to continuously track the DNS poisoning attack.

## Scheduling with Cron

To schedule the DNS monitoring script to run at regular intervals, you can use cron:

1. Edit your crontab:
   ```bash
   crontab -e
   ```

2. Add an entry to run the monitoring script every hour:
   ```
   # Run DNS monitoring every hour
   0 * * * * cd /path/to/dns-monitor && make cron > /dev/null 2>&1
   ```

3. For more frequent monitoring (every 10 minutes):
   ```
   # Run DNS monitoring every 10 minutes
   */10 * * * * cd /path/to/dns-monitor && make cron > /dev/null 2>&1
   ```

## Run Modes

The DNS monitoring script supports several run modes:

- **Single Execution Mode** (`--once`): Run the script once and exit. This is the default mode used by `make run`.
  ```bash
  ./dns_monitor.sh --once
  ```

- **Cron Mode** (`--cron`): Designed for scheduled execution with minimal output. This is used by `make cron`.
  ```bash
  ./dns_monitor.sh --cron
  ```

- **Test Mode** (`--test`): Uses a temporary test directory for output files. Used by the test suite.
  ```bash
  ./dns_monitor.sh --test
  ```

## Log Rotation

To prevent logs and data files from consuming too much disk space, consider implementing log rotation:

```bash
# Example logrotate config for DNS monitoring
/path/to/dns-monitor/data/*/alerts.log {
  daily
  rotate 7
  compress
  missingok
  notifempty
}
```

## Email Notifications

To receive email notifications when poisoning is detected:

1. Update the configuration in `config.sh`:
   ```bash
   SEND_EMAIL=true
   EMAIL_RECIPIENT="your-email@example.com"
   ```

2. Ensure a working mail transfer agent (MTA) is installed on your system.

## Dashboard Integration

For real-time monitoring, consider setting up a simple web dashboard:

1. Create a symlink from your web server's document root to the reports directory:
   ```bash
   ln -s /path/to/dns-monitor/reports /var/www/html/dns-monitor
   ```

2. Access the dashboard at `http://your-server/dns-monitor/`

## Security Considerations

- Run the monitoring from multiple geographic locations to detect geographically targeted attacks
- Use different DNS resolvers to compare results
- Protect the monitoring server from tampering
- Consider using HTTPS for transferring monitoring data to a central location