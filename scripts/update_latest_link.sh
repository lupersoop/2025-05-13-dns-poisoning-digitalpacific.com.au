#!/bin/bash
#
# Update the 'latest' symlink to point to the most recent data directory
#

set -e

# Get the script directory and root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${ROOT_DIR}/data"
REPORTS_DIR="${ROOT_DIR}/reports"

# Make sure we have a reports directory
mkdir -p "${REPORTS_DIR}/daily"

# Find the most recent data directory (format: YYYY-MM-DD)
LATEST_DIR=$(find "${DATA_DIR}" -maxdepth 1 -type d -name "20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]" | sort -r | head -1)

if [ -z "$LATEST_DIR" ]; then
  echo "No data directories found in ${DATA_DIR}"
  exit 1
fi

echo "Found latest data directory: $LATEST_DIR"

# Create or update the 'latest' symlink
rm -f "${DATA_DIR}/latest"
ln -sf "$(basename "$LATEST_DIR")" "${DATA_DIR}/latest"
echo "Updated 'latest' symlink to point to $(basename "$LATEST_DIR")"

# Create or update report symlinks
# For the daily summary
if [ -f "${DATA_DIR}/latest/daily_summary.md" ]; then
  ln -sf "../data/latest/daily_summary.md" "${REPORTS_DIR}/daily/daily_summary.md"
  echo "Linked daily summary report"
fi

# For the alerts log
if [ -f "${DATA_DIR}/latest/alerts.log" ]; then
  ln -sf "../data/latest/alerts.log" "${REPORTS_DIR}/daily/alerts.log"
  echo "Linked alerts log"
fi

# For the summary CSV
if [ -f "${DATA_DIR}/latest/summary.csv" ]; then
  ln -sf "../data/latest/summary.csv" "${REPORTS_DIR}/daily/summary.csv"
  echo "Linked summary CSV"
fi

# For HTTPS mirror report
if [ -f "${DATA_DIR}/latest/https/mirror_https_report.md" ]; then
  ln -sf "../data/latest/https/mirror_https_report.md" "${REPORTS_DIR}/daily/mirror_https_report.md"
  echo "Linked HTTPS mirror report"
fi

echo "Report links updated successfully."