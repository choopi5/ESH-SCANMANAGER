import requests
from functools import lru_cache

BGPVIEW_ASN = "https://api.bgpview.io/asn/{}/prefixes"

def ip_to_asn(ip, reader) -> str | None:
    try:
        data = reader.get(ip)
        if data and 'asn' in data:
            return f"AS{data['asn']}"
    except:
        pass
    return None

@lru_cache(maxsize=1000)
def asn_prefixes(asn: str) -> set:
    cidrs = set()
    try:
        r = requests.get(BGPVIEW_ASN.format(asn[2:]), timeout=10).json()
        cidrs |= {p["prefix"] for p in r["data"].get("ipv4_prefixes", [])}
    except:
        pass
    return cidrs
