import requests
from tqdm import tqdm

def get_bulk_whois_info(prefixes: list[str], batch_size=100) -> dict:
    data = {}
    for i in range(0, len(prefixes), batch_size):
        batch = prefixes[i:i + batch_size]
        print(f"[+] WHOIS batch {i//batch_size + 1}")
        for prefix in tqdm(batch, unit="cidr"):
            ip = prefix.split('/')[0]
            try:
                r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10).json()
                data[ip] = {
                    'org': r.get('org', ''),
                    'asn_description': r.get('org', ''),
                    'network': r.get('hostname', '')
                }
            except:
                data[ip] = {}
    return data

def filter_prefixes_by_org(prefixes: set[str], org_regex, whois_data: dict) -> set:
    matches = set()
    for prefix in prefixes:
        ip = prefix.split('/')[0]
        data = whois_data.get(ip, {})
        org_fields = [data.get(k, '') for k in ['org', 'asn_description', 'network']]
        if any(org_regex.search(f) for f in org_fields if f):
            matches.add(prefix)
    return matches
