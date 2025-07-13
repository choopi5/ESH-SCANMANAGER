import requests
import socket
import json
from tqdm import tqdm
from pathlib import Path

def get_ips_from_dns(domain: str) -> set:
    ips = set()
    try:
        ip = socket.gethostbyname(domain)
        ips.add(ip)
    except socket.gaierror:
        pass
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                         headers={"accept": "application/dns-json"}, timeout=5).json()
        ips |= {a["data"] for a in r.get("Answer", []) if a["type"] == 1}
    except:
        pass
    return ips

def process_domain_batch(domains: list, batch_size=50, ips_file=None) -> set:
    all_ips = set()
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        print(f"[+] Processing batch {i//batch_size + 1}")
        for d in tqdm(batch, unit="domain"):
            new_ips = get_ips_from_dns(d)
            if new_ips:
                all_ips |= new_ips
        if ips_file:
            Path(ips_file).write_text(json.dumps(list(all_ips)))
    return all_ips
