#!/usr/bin/env python3
"""
org_ip_discover.py
Passive discovery of all IP space likely owned by a target organisation.

USAGE
-----
python org_ip_discover.py -i domains.txt -o cidrs.txt --org "ACME CORP"

DEPENDENCIES
------------
pip install requests tqdm maxminddb
Optional CLIs on PATH:
  * dnsdbq   – for Passive DNS expansion          (see dnsdbq docs)
  * asnmap   – alternative ASN→CIDR expander      (see asnmap docs)

© 2025 – released under MIT
"""
import argparse, json, re, subprocess, sys, time
from pathlib import Path
from random import sample
from config import (
    IP_INFO_TOKEN, IPWHOIS_API_KEY,
    IPWHOIS_BULK_URL, IPWHOIS_ASN_URL
)
import maxminddb
import ipwhois
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError

import requests
from tqdm import tqdm
from functools import lru_cache
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, List

IPINFO_URL  = "https://ipinfo.io/{}/json"
BGPVIEW_ASN = "https://api.bgpview.io/asn/{}/prefixes"
CRT_SH      = "https://crt.sh/?q=%25{}&output=json"   # %25 is URL-encoded '%'

# Add cache file path
WHOIS_CACHE_FILE = "whois_cache.json"

def save_intermediate(data, filename):
    """Save intermediate data to a JSON file"""
    if not data:  # Don't save empty sets
        return
    with open(filename, 'w') as f:
        json.dump(list(data), f)

def load_intermediate(filename):
    """Load intermediate data from a JSON file"""
    try:
        with open(filename, 'r') as f:
            data = set(json.load(f))
            if not data:  # Don't return empty sets
                return None
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def process_domain_batch(domains, batch_size=50, ips_file=None):
    """Process a batch of domains and return discovered IPs using multiple methods."""
    all_ips = set()
    domain_results = {}  # Track IPs per domain
    
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        print(f"[+] Processing batch {i//batch_size + 1}/{(len(domains) + batch_size - 1)//batch_size}")
        
        for d in tqdm(batch, unit="domain"):
            domain_ips = set()
            
            # Try DNSDB first
            if new_ips := dnsdb_ips(d):
                domain_ips |= new_ips
                print(f"[+] Found {len(new_ips)} IPs for {d} using DNSDB")
            
            # If DNSDB fails, try direct DNS methods
            if not domain_ips:
                if new_ips := get_ips_from_dns(d):
                    domain_ips |= new_ips
                    print(f"[+] Found {len(new_ips)} IPs for {d} using direct DNS")
            
            # Store results
            if domain_ips:
                domain_results[d] = domain_ips
                all_ips |= domain_ips
            else:
                print(f"[!] No IPs found for {d}")
        
        # Save intermediate results if file path provided
        if ips_file:
            save_intermediate(all_ips, ips_file)
        
        # Report batch progress
        print(f"\n[+] Batch {i//batch_size + 1} Summary:")
        print(f"  - Domains processed: {len(batch)}")
        print(f"  - Domains with IPs: {sum(1 for d in batch if d in domain_results)}")
        print(f"  - Total IPs so far: {len(all_ips)}")
    
    # Final report
    print("\n[+] IP Collection Summary:")
    print(f"  - Total domains: {len(domains)}")
    print(f"  - Domains with IPs: {len(domain_results)}")
    print(f"  - Domains without IPs: {len(domains) - len(domain_results)}")
    print(f"  - Total unique IPs: {len(all_ips)}")
    
    # Show domains without IPs
    domains_without_ips = set(domains) - set(domain_results.keys())
    if domains_without_ips:
        print("\n[!] Domains without IPs:")
        for d in sorted(domains_without_ips)[:10]:  # Show first 10
            print(f"  - {d}")
        if len(domains_without_ips) > 10:
            print(f"  ... and {len(domains_without_ips) - 10} more")
    
    return all_ips

def enrich_with_crtsh(domains, existing_ips, batch_size=50):
    """Optional enrichment step using crt.sh"""
    new_ips = set()
    print("[+] Enriching results with crt.sh data")
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        print(f"[+] Processing crt.sh batch {i//batch_size + 1}/{(len(domains) + batch_size - 1)//batch_size}")
        for d in tqdm(batch, unit="domain"):
            if crtsh_ips := passive_cert_ips(d):
                new_ips |= crtsh_ips
    return new_ips - existing_ips  # Only return new IPs we didn't already have

def validate_intermediate_files(ips_file, asns_file, cidrs_file):
    """Validate intermediate files and determine recovery point"""
    if not ips_file.exists():
        return "start"
    
    ips = load_intermediate(ips_file)
    if not ips:
        return "start"
    
    if not asns_file.exists():
        return "asn"
    
    asns = load_intermediate(asns_file)
    if not asns:
        return "asn"
    
    if not cidrs_file.exists():
        return "cidr"
    
    cidrs = load_intermediate(cidrs_file)
    if not cidrs:
        return "cidr"
    
    return "filter"

# --------------------------------------------------------------------------- #
def passive_cert_ips(domain: str) -> set[str]:
    """Return IPs seen in certificates for *domain* and its sub-names."""
    try:
        r = requests.get(CRT_SH.format(domain), timeout=20)
        if r.status_code != 200:
            return set()
        hosts = {h.lower() for row in r.json() for h in row["name_value"].split()}
    except Exception:
        return set()
    ips = set()
    for h in hosts:
        try:
            # DNS over HTTPS (Cloudflare) – still "active", but no packets to target.
            d = requests.get(f"https://cloudflare-dns.com/dns-query?name={h}&type=A",
                             headers={"accept": "application/dns-json"}, timeout=10).json()
            ips |= {a["data"] for a in d.get("Answer", []) if a["type"] == 1}
        except Exception:
            pass
    return ips

def dnsdb_ips(domain: str) -> set[str]:
    """Use dnsdbq if available; otherwise return empty set."""
    if not shutil.which("dnsdbq"):
        print(f"[!] dnsdbq not found in PATH for {domain}")
        return set()
    try:
        out = subprocess.check_output(
            ["dnsdbq", "-r", domain, "-A", "-j"], text=True, timeout=60
        )
        ips = {row["rdata"] for row in json.loads(out)}
        if not ips:
            print(f"[!] No DNSDB results for {domain}")
        return ips
    except subprocess.CalledProcessError as e:
        print(f"[!] dnsdbq failed for {domain}: {str(e)}")
        return set()
    except json.JSONDecodeError:
        print(f"[!] Invalid JSON from dnsdbq for {domain}")
        return set()
    except Exception as e:
        print(f"[!] Unexpected error with dnsdbq for {domain}: {str(e)}")
        return set()

def get_ips_from_dns(domain: str) -> set[str]:
    """Get IPs using various DNS methods."""
    ips = set()
    
    # Try direct DNS lookup first
    try:
        import socket
        try:
            ip = socket.gethostbyname(domain)
            ips.add(ip)
        except socket.gaierror:
            pass
    except Exception:
        pass

    # Try Cloudflare DNS over HTTPS
    try:
        d = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                         headers={"accept": "application/dns-json"}, timeout=10).json()
        ips |= {a["data"] for a in d.get("Answer", []) if a["type"] == 1}
    except Exception:
        pass

    return ips

def ip_to_asn(ip: str, reader: maxminddb.Reader) -> str | None:
    """Return ASN string (e.g. 'AS15169') for an IP using MMDB."""
    try:
        data = reader.get(ip)
        if data and 'asn' in data:
            return f"AS{data['asn']}"
        return None
    except Exception:
        return None

@lru_cache(maxsize=1000)
def get_asn_prefixes_ipwhois(asn: str) -> set[str]:
    """Get prefixes for an ASN using ipwhois.pro API."""
    try:
        # Remove 'AS' prefix if present
        asn_num = asn[2:] if asn.startswith('AS') else asn
        
        # Make request to ipwhois.pro ASN endpoint
        response = requests.get(
            IPWHOIS_ASN_URL,
            params={
                "key": IPWHOIS_API_KEY,
                "asn": asn_num
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success", False) and "prefixes" in data:
                prefixes = {p["prefix"] for p in data["prefixes"]}
                if prefixes:
                    print(f"[+] Found {len(prefixes)} prefixes for {asn} via ipwhois.pro")
                    return prefixes
        else:
            print(f"[!] ipwhois.pro API request failed for {asn}: {response.status_code}")
    except Exception as e:
        print(f"[!] Error getting prefixes for {asn}: {str(e)}")
    return set()

def get_bulk_asn_prefixes(asns: list[str], batch_size: int = 10) -> dict[str, set[str]]:
    """Get prefixes for multiple ASNs in bulk."""
    results = {}
    for i in range(0, len(asns), batch_size):
        batch = asns[i:i + batch_size]
        print(f"\nProcessing ASN batch {i//batch_size + 1}/{(len(asns) + batch_size - 1)//batch_size}")
        
        try:
            # Make bulk request
            response = requests.post(
                IPWHOIS_BULK_URL,
                json=[{"asn": asn[2:] if asn.startswith('AS') else asn} for asn in batch],
                params={"key": IPWHOIS_API_KEY},
                timeout=30
            )
            
            if response.status_code == 200:
                batch_results = response.json()
                for data in batch_results:
                    asn = f"AS{data.get('asn')}"
                    if data.get("success", False) and "prefixes" in data:
                        results[asn] = {p["prefix"] for p in data["prefixes"]}
                        print(f"[+] Found {len(results[asn])} prefixes for {asn}")
                    else:
                        results[asn] = set()
                        print(f"[!] No prefixes found for {asn}")
            else:
                print(f"[!] Bulk API request failed: {response.status_code}")
                for asn in batch:
                    results[asn] = set()
            
            # Rate limiting
            if i + batch_size < len(asns):
                time.sleep(1)
                
        except Exception as e:
            print(f"[!] Error processing batch: {str(e)}")
            for asn in batch:
                results[asn] = set()
    
    return results

def asn_prefixes(asn: str, token: str | None = None) -> set[str]:
    """Return {CIDR,...} for an ASN via multiple methods."""
    cidrs = set()
    
    # Try ipwhois.pro first (fastest and most reliable)
    if new_cidrs := get_asn_prefixes_ipwhois(asn):
        cidrs |= new_cidrs
        if cidrs:
            return cidrs
    
    # Try IPinfo if token available
    if IP_INFO_TOKEN:
        try:
            url = f"https://ipinfo.io/{asn}/json?token={IP_INFO_TOKEN}"
            j = requests.get(url, timeout=10).json()
            if "prefixes" in j:
                cidrs |= {p["ipv4_prefix"] for p in j["prefixes"]}
                if cidrs:
                    print(f"[+] Found {len(cidrs)} prefixes for {asn} via IPinfo")
                    return cidrs
        except Exception as e:
            print(f"[!] IPinfo lookup failed for {asn}: {str(e)}")
    
    # Try BGPView as last resort
    try:
        j = requests.get(BGPVIEW_ASN.format(asn[2:]), timeout=10).json()
        if "data" in j and "ipv4_prefixes" in j["data"]:
            cidrs |= {p["prefix"] for p in j["data"]["ipv4_prefixes"]}
            if cidrs:
                print(f"[+] Found {len(cidrs)} prefixes for {asn} via BGPView")
                return cidrs
    except Exception as e:
        print(f"[!] BGPView lookup failed for {asn}: {str(e)}")
    
    if not cidrs:
        print(f"[!] No prefixes found for {asn} via any method")
    
    return cidrs

def org_string_in_whois(prefix: str, org_regex: re.Pattern) -> bool:
    """Check if organization name matches in WHOIS data using ipwhois."""
    try:
        # Get first IP from prefix for lookup
        ip = prefix.split('/')[0]
        obj = IPWhois(ip)
        results = obj.lookup_whois()
        
        # Check various WHOIS fields for organization name
        org_fields = [
            results.get('nets', [{}])[0].get('description', ''),
            results.get('nets', [{}])[0].get('name', ''),
            results.get('asn_description', ''),
            results.get('nets', [{}])[0].get('org', '')
        ]
        
        # Check if any field matches the regex
        return any(org_regex.search(field) for field in org_fields if field)
    except (IPDefinedError, ASNRegistryError) as e:
        print(f"[!] WHOIS lookup failed for {prefix}: {str(e)}")
        return False
    except Exception as e:
        print(f"[!] Unexpected error with WHOIS for {prefix}: {str(e)}")
        return False

# --------------------------------------------------------------------------- #
def load_whois_cache() -> Dict[str, dict]:
    """Load WHOIS results from cache file."""
    if os.path.exists(WHOIS_CACHE_FILE):
        try:
            with open(WHOIS_CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Error loading cache: {str(e)}")
    return {}

def save_whois_cache(cache: Dict[str, dict]):
    """Save WHOIS results to cache file."""
    try:
        with open(WHOIS_CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except Exception as e:
        print(f"[!] Error saving cache: {str(e)}")

def process_whois_batch(batch_ips: List[str], cache: Dict[str, dict], batch_num: int, total_batches: int) -> Dict[str, dict]:
    """Process a single batch of WHOIS lookups."""
    results = {}
    uncached_ips = []
    
    # Check cache first
    for ip in batch_ips:
        if ip in cache:
            results[ip] = cache[ip]
        else:
            uncached_ips.append(ip)
    
    if not uncached_ips:
        print(f"[+] Batch {batch_num}/{total_batches}: All IPs found in cache")
        return results
    
    print(f"[+] Batch {batch_num}/{total_batches}: Processing {len(uncached_ips)} uncached IPs")
    
    try:
        response = requests.post(
            IPWHOIS_BULK_URL,
            json=uncached_ips,
            headers={"Content-Type": "application/json"},
            params={"key": IPWHOIS_API_KEY},
            timeout=120
        )
        
        if response.status_code == 200:
            batch_results = response.json()
            if isinstance(batch_results, list):
                success_count = 0
                new_cache_entries = {}  # Store new cache entries separately
                
                for data in batch_results:
                    if not isinstance(data, dict):
                        continue
                    
                    ip = data.get('ip')
                    if not ip:
                        continue
                    
                    if data.get("success", False):
                        result = {
                            'org': data.get('connection', {}).get('org', ''),
                            'asn': str(data.get('connection', {}).get('asn', '')),
                            'asn_description': data.get('connection', {}).get('domain', ''),
                            'network': data.get('connection', {}).get('isp', '')
                        }
                        results[ip] = result
                        new_cache_entries[ip] = result  # Store in separate dict
                        success_count += 1
                    else:
                        results[ip] = {}
                
                print(f"[+] Batch {batch_num}/{total_batches}: Successfully processed {success_count}/{len(uncached_ips)} IPs")
                
                # Update cache with new results (safely)
                if new_cache_entries:
                    cache.update(new_cache_entries)
                    save_whois_cache(cache)
            else:
                print(f"[!] Invalid response format for batch {batch_num}")
        else:
            print(f"[!] Bulk WHOIS API request failed: {response.status_code}")
            
    except Exception as e:
        print(f"[!] Error in batch {batch_num}: {str(e)}")
    
    return results

def get_bulk_whois_info(prefixes: list[str], batch_size: int = 100, max_workers: int = 5) -> dict[str, dict]:
    """Get WHOIS info for multiple prefixes in bulk using ipwhois.pro API with caching and parallel processing."""
    # Deduplicate IPs first
    unique_ips = list(set(prefix.split('/')[0] for prefix in prefixes))
    print(f"\n[+] Found {len(unique_ips)} unique IPs out of {len(prefixes)} prefixes")
    
    # Load cache
    cache = load_whois_cache()
    print(f"[+] Loaded {len(cache)} cached WHOIS results")
    
    # Calculate batches
    total_batches = (len(unique_ips) + batch_size - 1) // batch_size
    print(f"[+] Processing {len(unique_ips)} IPs in {total_batches} batches of {batch_size}")
    
    results = {}
    
    try:
        # Process batches in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i in range(0, len(unique_ips), batch_size):
                batch = unique_ips[i:i + batch_size]
                batch_num = i // batch_size + 1
                futures.append(
                    executor.submit(process_whois_batch, batch, cache, batch_num, total_batches)
                )
            
            # Collect results
            for future in as_completed(futures):
                try:
                    batch_results = future.result()
                    results.update(batch_results)
                except Exception as e:
                    print(f"[!] Error processing batch: {str(e)}")
        
    except Exception as e:
        print(f"[!] Bulk API failed: {str(e)}")
        print("[+] Falling back to direct WHOIS lookups...")
        
        # Fallback to direct WHOIS lookups
        for prefix in tqdm(prefixes, unit="prefix"):
            try:
                ip = prefix.split('/')[0]
                if ip in cache:
                    results[ip] = cache[ip]
                    continue
                    
                obj = IPWhois(ip)
                whois_results = obj.lookup_whois()
                
                if whois_results and 'nets' in whois_results and whois_results['nets']:
                    net = whois_results['nets'][0]
                    result = {
                        'org': net.get('description', ''),
                        'asn': whois_results.get('asn', ''),
                        'asn_description': whois_results.get('asn_description', ''),
                        'network': net.get('cidr', '')
                    }
                    results[ip] = result
                    cache[ip] = result  # Update cache
                    save_whois_cache(cache)
                else:
                    results[ip] = {}
                    
            except Exception as e:
                print(f"[!] WHOIS lookup failed for {ip}: {str(e)}")
                results[ip] = {}
            
            time.sleep(1)
    
    return results

def analyze_whois_data(whois_data: dict[str, dict]):
    """Analyze WHOIS data to help with organization matching."""
    print("\n[+] Analyzing WHOIS data patterns:")
    
    # Collect all unique organization names
    orgs = set()
    asn_descs = set()
    networks = set()
    
    for data in whois_data.values():
        if org := data.get('org', ''):
            orgs.add(org)
        if asn_desc := data.get('asn_description', ''):
            asn_descs.add(asn_desc)
        if network := data.get('network', ''):
            networks.add(network)
    
    print("\n[+] Found organization names:")
    for org in sorted(orgs)[:10]:  # Show first 10
        print(f"  - {org}")
    if len(orgs) > 10:
        print(f"  ... and {len(orgs) - 10} more")
    
    print("\n[+] Found ASN descriptions:")
    for desc in sorted(asn_descs)[:10]:  # Show first 10
        print(f"  - {desc}")
    if len(asn_descs) > 10:
        print(f"  ... and {len(asn_descs) - 10} more")
    
    print("\n[+] Found network names:")
    for net in sorted(networks)[:10]:  # Show first 10
        print(f"  - {net}")
    if len(networks) > 10:
        print(f"  ... and {len(networks) - 10} more")
    
    print("\n[+] Suggested patterns:")
    print("1. Try matching the exact organization name")
    print("2. Try matching part of the organization name")
    print("3. Try matching the ASN description")
    print("4. Try matching the network name")
    print("\nExample patterns:")
    print("  - Exact match: 'Organization Name'")
    print("  - Partial match: 'Organization.*'")
    print("  - Multiple fields: '(Organization|Network).*'")
    print("  - Case insensitive: '(?i)organization'")

def filter_prefixes_by_org(prefixes: set[str], org_regex: re.Pattern, batch_size: int = 100) -> set[str]:
    """Filter prefixes by organization name using bulk WHOIS lookup."""
    print(f"[+] Getting WHOIS info for {len(prefixes)} prefixes")
    whois_data = get_bulk_whois_info(list(prefixes), batch_size)
    
    # Analyze WHOIS data to help with pattern matching
    analyze_whois_data(whois_data)
    
    print("\n[+] Filtering prefixes by organization name")
    print(f"[+] Organization pattern: {org_regex.pattern}")
    
    # Common cloud providers and CDNs to filter out
    cloud_providers = {
        # Global Cloud Providers
        'amazon', 'aws', 'cloudfront', 'azure', 'microsoft', 'google cloud',
        'cloudflare', 'akamai', 'fastly', 'cloud', 'hosting', 'datacenter',
        'colo', 'colocation', 'isp', 'internet service provider',
        
        # Indian ISPs and Telecom
        'tata', 'tatacommunications', 'tatatel', 'tataindicom', 'tatadocomo',
        'reliance', 'jio', 'airtel', 'vodafone', 'idea', 'bsnl', 'mtnl',
        'sify', 'railwire', 'youbroadband', 'act', 'asianet', 'hathway',
        
        # Global ISPs and Telecom
        'verizon', 'at&t', 'comcast', 'centurylink', 'level3', 'cogent',
        'nordunet', 'telia', 'deutsche telekom', 'orange', 'telefonica',
        'bt', 'virgin', 'sky', 'talktalk', 'plusnet', 'ee', 'o2',
        
        # Hosting and Datacenter
        'hosting', 'datacenter', 'colo', 'colocation', 'server', 'rack',
        'equinix', 'digital realty', 'interxion', 'telehouse', 'telecity',
        'global switch', 'cyrusone', 'qts', 'core site', 'switch',
        
        # CDN and Network
        'cdn', 'content delivery', 'edge', 'network', 'backbone', 'transit',
        'peering', 'exchange', 'ix', 'internet exchange', 'carrier',
        
        # Common Terms
        'hosting', 'provider', 'services', 'solutions', 'technologies',
        'communications', 'telecom', 'telecommunications', 'network',
        'infrastructure', 'datacenter', 'colocation', 'cloud', 'isp'
    }
    
    matching_prefixes = set()
    non_matching_examples = []  # Store some non-matching examples
    cloud_provider_matches = []  # Store cloud provider matches
    
    for prefix in tqdm(prefixes, unit="prefix"):
        ip = prefix.split('/')[0]
        if ip in whois_data:
            data = whois_data[ip]
            # Check various WHOIS fields for organization name
            org_fields = [
                data.get('org', ''),
                data.get('asn_description', ''),
                data.get('network', '')
            ]
            
            # Check for cloud providers
            is_cloud = any(provider in ' '.join(org_fields).lower() for provider in cloud_providers)
            
            # Store examples
            if len(non_matching_examples) < 5 and not any(org_regex.search(field) for field in org_fields if field):
                non_matching_examples.append((ip, org_fields))
            
            if is_cloud:
                if len(cloud_provider_matches) < 5:
                    cloud_provider_matches.append((ip, org_fields))
                continue
            
            # Check for organization match
            if any(org_regex.search(field) for field in org_fields if field):
                matching_prefixes.add(prefix)
                print(f"[+] Found match for {prefix}: {next((f for f in org_fields if f and org_regex.search(f)), '')}")
    
    if not matching_prefixes:
        print("\n[!] No matching CIDRs found. Please check your organization name pattern.")
        print("\n[+] Example non-matching WHOIS data:")
        for ip, fields in non_matching_examples:
            print(f"\nIP: {ip}")
            print(f"  Org: {fields[0]}")
            print(f"  ASN Desc: {fields[1]}")
            print(f"  Network: {fields[2]}")
        
        print("\n[+] Suggestions:")
        print("1. Try a more general pattern (e.g., 'Company' instead of 'Company Inc.')")
        print("2. Check for common variations in the organization name")
        print("3. Try matching partial names (e.g., 'Company.*' or '.*Company')")
        print("4. Consider case sensitivity (use (?i) for case-insensitive matching)")
    else:
        print(f"\n[+] Found {len(matching_prefixes)} matching CIDRs")
        if cloud_provider_matches:
            print("\n[!] Filtered out cloud provider matches:")
            for ip, fields in cloud_provider_matches:
                print(f"\nIP: {ip}")
                print(f"  Org: {fields[0]}")
                print(f"  ASN Desc: {fields[1]}")
                print(f"  Network: {fields[2]}")
    
    return matching_prefixes

def resolve_domain(domain: str, max_retries: int = 3) -> set[str]:
    """Resolve domain using multiple methods with retries."""
    ips = set()
    
    # Try direct DNS lookup
    for _ in range(max_retries):
        try:
            import socket
            try:
                ip = socket.gethostbyname(domain)
                ips.add(ip)
                break  # Success, no need to retry
            except socket.gaierror:
                time.sleep(1)  # Wait before retry
        except Exception:
            time.sleep(1)
    
    # Try Cloudflare DNS over HTTPS
    for _ in range(max_retries):
        try:
            d = requests.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
                headers={"accept": "application/dns-json"},
                timeout=10
            ).json()
            for answer in d.get("Answer", []):
                if answer["type"] == 1:
                    ips.add(answer["data"])
            break  # Success, no need to retry
        except Exception:
            time.sleep(1)
    
    # Try Google DNS over HTTPS
    for _ in range(max_retries):
        try:
            d = requests.get(
                f"https://dns.google/resolve?name={domain}&type=A",
                timeout=10
            ).json()
            for answer in d.get("Answer", []):
                if answer["type"] == 1:
                    ips.add(answer["data"])
            break  # Success, no need to retry
        except Exception:
            time.sleep(1)
    
    return ips

def verify_ips(domains: list[str], all_ips: set[str]):
    """Verify IP coverage by checking each domain."""
    print("\n[+] Verifying IP coverage:")
    missing_ips = set()
    found_ips = set()
    unresolved_domains = []
    
    for domain in tqdm(domains, unit="domain"):
        domain_ips = resolve_domain(domain)
        
        if not domain_ips:
            unresolved_domains.append(domain)
            continue
        
        # Check which IPs are in our set
        for ip in domain_ips:
            if ip in all_ips:
                found_ips.add(ip)
            else:
                missing_ips.add(ip)
                print(f"[!] Missing IP for {domain}: {ip}")
    
    # Report results
    print(f"\n[+] IP Coverage Report:")
    print(f"  - Total domains checked: {len(domains)}")
    print(f"  - Domains resolved: {len(domains) - len(unresolved_domains)}")
    print(f"  - Domains unresolved: {len(unresolved_domains)}")
    print(f"  - IPs found in our set: {len(found_ips)}")
    print(f"  - IPs missing from our set: {len(missing_ips)}")
    
    if unresolved_domains:
        print(f"\n[!] Could not resolve {len(unresolved_domains)} domains:")
        for domain in sorted(unresolved_domains)[:10]:  # Show first 10
            print(f"  - {domain}")
        if len(unresolved_domains) > 10:
            print(f"  ... and {len(unresolved_domains) - 10} more")
    
    if missing_ips:
        print(f"\n[!] Found {len(missing_ips)} missing IPs:")
        for ip in sorted(missing_ips):
            print(f"  - {ip}")
        
        # Add missing IPs to the set
        all_ips.update(missing_ips)
        print(f"\n[+] Updated IP set now contains {len(all_ips)} IPs")
    else:
        print("\n[✓] All resolved domains have their IPs in the set")
    
    return found_ips, missing_ips, unresolved_domains

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--infile", required=True, help="file of domains")
    ap.add_argument("-o", "--outfile", default="organisation_cidrs.txt")
    ap.add_argument("--org", required=True,
                    help="String/regex to match owning organisation in WHOIS/RDAP")
    ap.add_argument("--batch-size", type=int, default=100,
                    help="Number of IPs to process in each batch (default: 100)")
    ap.add_argument("--max-workers", type=int, default=5,
                    help="Maximum number of parallel workers (default: 5)")
    ap.add_argument("--mmdb", default="ipinfo_lite.mmdb",
                    help="Path to IPinfo Lite MMDB file")
    ap.add_argument("--enrich", action="store_true",
                    help="Enrich results with crt.sh data after main processing")
    ap.add_argument("--skip-dnsdb", action="store_true",
                    help="Skip DNSDB and use direct DNS methods only")
    ap.add_argument("--workers", type=int, default=10,
                    help="Number of parallel workers for ASN processing")
    ap.add_argument("--skip-ipwhois", action="store_true",
                    help="Skip IPWhois and use IPinfo/BGPView only")
    ap.add_argument("--retry-failed", action="store_true",
                    help="Retry failed ASN lookups with alternative methods")
    ap.add_argument("--case-sensitive", action="store_true",
                    help="Use case-sensitive matching for organization name")
    ap.add_argument("--clean", action="store_true",
                    help="Clean up intermediate files after completion")
    args = ap.parse_args()

    # Setup intermediate file paths
    base_path = Path(args.outfile).parent
    ips_file = base_path / "intermediate_ips.json"
    asns_file = base_path / "intermediate_asns.json"
    cidrs_file = base_path / "intermediate_cidrs.json"
    final_ips_file = base_path / "final_ips.txt"  # New file for final IPs

    # Load or gather domains
    domains = [d.strip() for d in Path(args.infile).read_text().splitlines() if d.strip()]
    
    # Determine recovery point
    recovery_point = validate_intermediate_files(ips_file, asns_file, cidrs_file)
    print(f"[+] Recovery point: {recovery_point}")
    
    # Step 1: Gather IPs
    if recovery_point == "start":
        all_ips = set()
        if args.skip_dnsdb:
            print(f"[+] Gathering IPs using direct DNS methods for {len(domains)} domain(s)")
        else:
            print(f"[+] Gathering IPs using DNSDB and direct DNS for {len(domains)} domain(s)")
        
        all_ips = process_domain_batch(domains, args.batch_size, ips_file)
    else:
        print("[+] Loading previously gathered IPs")
        all_ips = load_intermediate(ips_file)
    
    if not all_ips:
        print("[!] No IPs found. Please check your input domains.")
        print("[!] Try running with --skip-dnsdb if DNSDB is not available")
        return

    print(f"[+] {len(all_ips)} unique seed IPs collected")

    # Step 2: Map IPs to ASNs using MMDB
    if recovery_point in ["start", "asn"]:
        asns = set()
        print("[+] Mapping IPs → ASNs using MMDB")
        with maxminddb.open_database(args.mmdb) as reader:
            for ip in tqdm(all_ips, unit="ip"):
                if asn := ip_to_asn(ip, reader):
                    asns.add(asn)
                    save_intermediate(asns, asns_file)
    else:
        print("[+] Loading previously mapped ASNs")
        asns = load_intermediate(asns_file)
    
    if not asns:
        print("[!] No ASNs found. Please check your IPs.")
        return
    
    print(f"[+] {len(asns)} unique ASNs")

    # Step 3: Get prefixes for ASNs
    if recovery_point in ["start", "asn", "cidr"]:
        cidrs = set()
        failed_asns = set()
        print("[+] Fetching prefixes for every ASN")
        for a in tqdm(asns, unit="asn"):
            new_cidrs = asn_prefixes(a)
            if new_cidrs:  # Only save if we found new CIDRs
                cidrs |= new_cidrs
                save_intermediate(cidrs, cidrs_file)
            else:
                failed_asns.add(a)
        
        # Retry failed ASNs if requested
        if args.retry_failed and failed_asns:
            print(f"[+] Retrying {len(failed_asns)} failed ASNs with different methods")
            for a in tqdm(failed_asns, unit="asn"):
                new_cidrs = asn_prefixes(a)
                if new_cidrs:
                    cidrs |= new_cidrs
                    save_intermediate(cidrs, cidrs_file)
    else:
        print("[+] Loading previously gathered CIDRs")
        cidrs = load_intermediate(cidrs_file)
    
    if not cidrs:
        print("[!] No CIDRs found. Please check your ASNs.")
        print("[!] Try running with --retry-failed to attempt different lookup methods")
        return

    print(f"[+] {len(cidrs)} raw prefixes before filtering")

    # Step 4: Filter prefixes
    print("[+] Filtering prefixes by org-name match using bulk WHOIS")
    # Make organization pattern case-insensitive by default
    if not args.case_sensitive:
        org_pattern = f"(?i){args.org}"
    else:
        org_pattern = args.org
        
    org_regex = re.compile(org_pattern)
    final = filter_prefixes_by_org(cidrs, org_regex, args.batch_size)

    # Save final results
    try:
        # Save CIDRs if any found
        if final:
            output_path = Path(args.outfile)
            output_path.write_text("\n".join(sorted(final)))
            print(f"[✓] {len(final)} candidate CIDRs written to {output_path}")
        else:
            print("[!] No matching CIDRs found, skipping CIDR file")
        
        # Save final IPs from intermediate file
        print("\n[+] Writing final IPs from collected data...")
        if ips_file.exists():
            with open(ips_file, 'r') as f:
                final_ips = set(json.load(f))
                final_ips_file.write_text("\n".join(sorted(final_ips)))
                print(f"[✓] {len(final_ips)} final IPs written to {final_ips_file}")
        else:
            print(f"[!] Could not find intermediate IPs file: {ips_file}")
            return
        
        # Verify the files were written
        if final and output_path.exists():
            print(f"[+] Verified CIDR file exists: {output_path}")
            print(f"[+] CIDR file size: {output_path.stat().st_size} bytes")
            print(f"[+] CIDR file last modified: {output_path.stat().st_mtime}")
            
        if final_ips_file.exists():
            print(f"[+] Verified IP file exists: {final_ips_file}")
            print(f"[+] IP file size: {final_ips_file.stat().st_size} bytes")
            print(f"[+] IP file last modified: {final_ips_file.stat().st_mtime}")
        else:
            print(f"[!] IP file was not created: {final_ips_file}")
            
    except Exception as e:
        print(f"[!] Error writing output files: {str(e)}")
        return

    # Clean up intermediate files only if --clean flag is set
    if args.clean:
        for f in [ips_file, asns_file, cidrs_file]:
            try:
                if f.exists():
                    f.unlink()
                    print(f"[+] Removed intermediate file: {f}")
            except FileNotFoundError:
                pass
            except Exception as e:
                print(f"[!] Error removing {f}: {str(e)}")
    else:
        print("\n[+] Keeping intermediate files for analysis:")
        print(f"  - IPs: {ips_file}")
        print(f"  - ASNs: {asns_file}")
        print(f"  - CIDRs: {cidrs_file}")
        print(f"  - Final IPs: {final_ips_file}")

if __name__ == "__main__":
    import shutil   # late import – only used in dnsdb_ips()
    main()
