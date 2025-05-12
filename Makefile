.PHONY: test clean clean-all clean-hashes debug run cron reports install help

# Default target
.DEFAULT_GOAL := help

# Variables
SHELL := /bin/bash
TEST_DIR := tests
DATA_DIR := data
REPORTS_DIR := reports
SCRIPTS_DIR := scripts

# Help message
help:
	@echo "DNS Monitoring System Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make test          - Run all tests"
	@echo "  make clean         - Clean up temporary files"
	@echo "  make clean-all     - Remove all monitoring data (use with caution!)"
	@echo "  make clean-hashes  - Move hash files to the hashes directory"
	@echo "  make debug         - Generate a debug report"
	@echo "  make run           - Run the DNS monitoring script once"
	@echo "  make cron          - Run in cron mode (for scheduled executions)"
	@echo "  make reports       - Update report symlinks"
	@echo "  make install       - Install dependencies"
	@echo "  make help          - Show this help message"

# Run tests
test:
	@echo "Running tests..."
	@$(TEST_DIR)/run_tests.sh

# Clean up temporary files
clean:
	@echo "Cleaning up temporary files..."
	@rm -rf $(TEST_DIR)/temp/*
	@rm -f $(TEST_DIR)/outputs/*
	@rm -f $(TEST_DIR)/debug_report_*.tar.gz
	@echo "Cleanup complete."

# Organize hash files into the hashes directory
clean-hashes:
	@echo "Organizing hash files..."
	@TODAY_DIR=$$(find $(DATA_DIR) -maxdepth 1 -type d -name "20[0-9][0-9]-[0-9][0-9]-[0-9][0-9]" | sort -r | head -1); \
	if [ -n "$$TODAY_DIR" ]; then \
		echo "Found latest data directory: $$TODAY_DIR"; \
		mkdir -p "$$TODAY_DIR/hashes"; \
		find "$$TODAY_DIR" -maxdepth 1 -name "previous_*.hash" -exec mv {} "$$TODAY_DIR/hashes/" \; 2>/dev/null || true; \
		echo "Moved hash files to $$TODAY_DIR/hashes/"; \
	else \
		echo "No data directory found."; \
	fi

# Reset everything - use with caution
clean-all: clean
	@echo "WARNING: This will remove all monitoring data!"
	@echo "Press Ctrl+C to cancel or Enter to continue..."
	@read
	@echo "Removing all monitoring data..."
	@find $(DATA_DIR) -type d -name "20*-*-*" -exec rm -rf {} \; 2>/dev/null || true
	@pkill -f dns_monitor.sh 2>/dev/null || true
	@echo "Reset complete."

# Generate debug report
debug:
	@echo "Generating debug report..."
	@$(TEST_DIR)/debug_report.sh

# Run the DNS monitoring script
run:
	@echo "Running DNS monitoring script..."
	@./dns_monitor.sh
	@if [ $$? -eq 0 ]; then \
		echo "Updating 'latest' link..."; \
		./scripts/update_latest_link.sh; \
	else \
		echo "Error running monitoring script. Skipping post-processing."; \
		exit 1; \
	fi
	@echo "Monitoring run completed successfully."

# Run the DNS monitoring script in cron mode (for scheduling)
cron:
	@echo "Running DNS monitoring script (cron mode)..."
	@./dns_monitor.sh --cron
	@if [ $$? -eq 0 ]; then \
		echo "Updating 'latest' link..."; \
		./scripts/update_latest_link.sh; \
	else \
		echo "Error running monitoring script. Skipping post-processing."; \
		exit 1; \
	fi

# Update 'latest' link and reports
reports:
	@echo "Updating 'latest' link and reports..."
	@./scripts/update_latest_link.sh

# Install dependencies
install:
	@echo "Checking for dependencies..."
	@if ! command -v bats &> /dev/null; then \
		echo "Bats not found. Please install bats-core:"; \
		echo "  https://github.com/bats-core/bats-core#installation"; \
		exit 1; \
	fi
	@if ! command -v dig &> /dev/null; then \
		echo "Dig not found. Please install bind-utils or dnsutils."; \
		exit 1; \
	fi
	@if ! command -v curl &> /dev/null; then \
		echo "Curl not found. Please install curl."; \
		exit 1; \
	fi
	@if ! command -v openssl &> /dev/null; then \
		echo "OpenSSL not found. Please install openssl."; \
		exit 1; \
	fi
	@echo "All dependencies installed."
