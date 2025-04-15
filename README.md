# Security Incident Log Parser

A Python-based log parser for detecting suspicious activity in log files using configurable pattern matching. Outputs suspicious entries and generates a summary report.

## Features
- Detects suspicious activity like SQL injection, XSS, and reconnaissance tools
- Uses a JSON file for defining pattern rules
- Parses any plain text log file (Squid, Snort, ASA, etc.)
- Generates a `report.txt` file with findings

## Usage
```bash
python parser.py sample_logs/access.log
```
