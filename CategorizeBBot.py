import re
import json
from pathlib import Path
import os

# Get the current script's directory
script_dir = Path(os.path.dirname(os.path.abspath(__file__)))

# Load files using relative paths
findings_text = (script_dir / "Data/bbot_findings.txt").read_text()
github_text = (script_dir / "Data/bbot_github.txt").read_text()
social_text = (script_dir / "Data/bbot_social.txt").read_text()

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

# Output to JSON files using relative paths
vuln_path = script_dir / "Data/vulnerabilities.json"
surface_path = script_dir / "Data/attack_surface.json"

with open(vuln_path, "w") as f:
    json.dump(vulnerabilities, f, indent=2)

with open(surface_path, "w") as f:
    json.dump(attack_surface, f, indent=2)
