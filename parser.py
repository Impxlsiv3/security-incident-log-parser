import sys
import json
from collections import defaultdict

def load_patterns(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def parse_log(log_file, patterns):
    suspicious_lines = defaultdict(list)
    ip_counter = defaultdict(int)

    with open(log_file, 'r') as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, 1):
        for category, terms in patterns.items():
            for term in terms:
                if term.lower() in line.lower():
                    suspicious_lines[category].append((line_num, line.strip()))
        if ' ' in line:
            ip = line.split(' ')[0]
            ip_counter[ip] += 1

    # Detect repeated IP hits
    for ip, count in ip_counter.items():
        if count > 10:
            suspicious_lines["Repeated IP"].append((0, f"IP {ip} appeared {count} times"))

    return suspicious_lines

def write_report(suspicious_lines, output="report.txt"):
    with open(output, 'w') as f:
        for category, entries in suspicious_lines.items():
            f.write(f"--- {category} ---\n")
            for line_num, content in entries:
                f.write(f"Line {line_num}: {content}\n")
            f.write("\n")
    print(f"Report written to {output}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parser.py <logfile>")
        sys.exit(1)

    patterns = load_patterns("patterns.json")
    suspicious = parse_log(sys.argv[1], patterns)
    write_report(suspicious)
