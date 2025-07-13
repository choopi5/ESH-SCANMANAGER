import json
import ipaddress
from pathlib import Path

def save_intermediate(data, filepath):
    Path(filepath).write_text(json.dumps(list(data)))

def load_intermediate(filepath):
    try:
        return set(json.loads(Path(filepath).read_text()))
    except:
        return set()

def resolve_domain(domain: str) -> set:
    import socket
    try:
        return {socket.gethostbyname(domain)}
    except:
        return set()

def intersect_prefixes_with_seed_ips(prefixes: set[str], seed_ips: set[str]) -> set[str]:
    valid = set()
    for prefix in prefixes:
        net = ipaddress.ip_network(prefix)
        if any(ipaddress.ip_address(ip) in net for ip in seed_ips):
            valid.add(prefix)
    return valid

def save_output_summary(outfile, domains, ips, asns, cidrs, org):
    summary = {
        "organization": org,
        "domains": len(domains),
        "unique_ips": len(ips),
        "unique_asns": len(asns),
        "filtered_cidrs": len(cidrs),
        "output_file": outfile
    }
    Path(outfile + ".summary.json").write_text(json.dumps(summary, indent=2))
