import re
import json
from pathlib import Path
import os
import sys

# Check if folder path is provided
if len(sys.argv) != 2:
    print("Usage: python CategorizeBBot.py <folder_path>")
    print("Example: python CategorizeBBot.py D:\\Ranger\\Scanner Environment\\ltimindtree_com\\leads")
    sys.exit(1)

folder_path = sys.argv[1]

# Construct file paths
findings_file = os.path.join(folder_path, 'bbot_findings.txt')
github_file = os.path.join(folder_path, 'bbot_github.txt')
social_file = os.path.join(folder_path, 'bbot_social.txt')

# Check if input files exist
if not os.path.exists(findings_file):
    print(f"Error: {findings_file} not found")
    sys.exit(1)

if not os.path.exists(github_file):
    print(f"Error: {github_file} not found")
    sys.exit(1)

if not os.path.exists(social_file):
    print(f"Error: {social_file} not found")
    sys.exit(1)

print(f"Processing files from: {folder_path}")
print(f"- Reading findings from: {findings_file}")
print(f"- Reading GitHub data from: {github_file}")
print(f"- Reading social data from: {social_file}")

# Load files
findings_text = open(findings_file, 'r').read()
github_text = open(github_file, 'r').read()
social_text = open(social_file, 'r').read()

# Define patterns
cve_pattern = re.compile(r"CVE-\d{4}-\d+")
serialized_pattern = re.compile(r"serialized object.*\b(PHP_Array)\b", re.IGNORECASE)
oauth_pattern = re.compile(r"https://[^\s]+/oauth2/token")
openid_pattern = re.compile(r"https://[^\s]+/.well-known/openid-configuration")
url_pattern = re.compile(r"https?://[^\s]+")

# Categorization results
categorized = []

# 1. Parse findings for CVEs, OpenID, OAuth, Serialized Objects
for line in findings_text.splitlines():
    cves = cve_pattern.findall(line)
    if cves:
        host_match = re.search(r"HOST:\s*([^\s]+)", line)
        categorized.append({
            "type": "vulnerability",
            "subtype": "cve",
            "host": host_match.group(1) if host_match else None,
            "data": {"cves": list(set(cves))}
        })
    elif serialized_pattern.search(line):
        url = url_pattern.search(line)
        categorized.append({
            "type": "vulnerability",
            "subtype": "serialized_object",
            "url": url.group(0) if url else None
        })
    elif openid_pattern.search(line):
        url = openid_pattern.search(line).group(0)
        categorized.append({
            "type": "attack_surface",
            "subtype": "openid_endpoint",
            "url": url
        })
    elif oauth_pattern.search(line):
        url = oauth_pattern.search(line).group(0)
        categorized.append({
            "type": "attack_surface",
            "subtype": "oauth_endpoint",
            "url": url
        })

# 2. Parse GitHub repos
for line in github_text.splitlines():
    if "github.com" in line:
        url = url_pattern.search(line)
        if url:
            categorized.append({
                "type": "attack_surface",
                "subtype": "public_code_repository",
                "url": url.group(0)
            })

# 3. Parse social/email info
for line in social_text.splitlines():
    if "@" in line and "EMAIL_ADDRESS" in line:
        email = line.split(":")[-1].strip()
        categorized.append({
            "type": "attack_surface",
            "subtype": "email_exposure",
            "email": email
        })

# Separate data by type
vulnerabilities = [entry for entry in categorized if entry['type'] == 'vulnerability']
attack_surface = [entry for entry in categorized if entry['type'] == 'attack_surface']

# Output to JSON files
vuln_path = os.path.join(folder_path, 'vulnerabilities.json')
surface_path = os.path.join(folder_path, 'attack_surface.json')

with open(vuln_path, "w") as f:
    json.dump(vulnerabilities, f, indent=2)

with open(surface_path, "w") as f:
    json.dump(attack_surface, f, indent=2)

print(f"\nProcessing complete!")
print(f"- Found {len(vulnerabilities)} vulnerabilities")
print(f"- Found {len(attack_surface)} attack surface items")
print(f"- Vulnerabilities saved to: {vuln_path}")
print(f"- Attack surface saved to: {surface_path}")
