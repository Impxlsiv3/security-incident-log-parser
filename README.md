# Security Incident Log Parser

A CLI-based log analysis tool that parses Squid, Snort, and general log files to flag suspicious activity (SQL injection, XSS, scanning). Outputs a detailed incident report using JSON-driven pattern matching.

## Features
- Detects suspicious activity like SQL injection, XSS, and reconnaissance tools
- Uses a JSON file for defining pattern rules
- Parses any plain text log file (Squid, Snort, ASA, etc.)
- Generates a `report.txt` file with findings

## Usage
```bash
python parser.py sample_logs/access.log
```
