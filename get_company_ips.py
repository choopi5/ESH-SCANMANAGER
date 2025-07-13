def get_company_ips(domains_file, output_file, company_name, batch_size=50):
    """
    Generate a comprehensive list of IPs from a seed list of domain names belonging to a single company.
    
    Args:
        domains_file (str): Path to file containing domain names, one per line
        output_file (str): Path where the final IP list will be saved
        company_name (str): Name of the company to filter results by (used for RDAP/WHOIS matching)
        batch_size (int): Number of domains to process in each batch (default: 50)
    """
    # Import required modules
    from pathlib import Path
    import json
    from tqdm import tqdm
    
    # Setup file paths
    base_path = Path(output_file).parent
    ips_file = base_path / "intermediate_ips.json"
    asns_file = base_path / "intermediate_asns.json"
    cidrs_file = base_path / "intermediate_cidrs.json"
    
    # Load domains
    domains = [d.strip() for d in Path(domains_file).read_text().splitlines() if d.strip()]
    print(f"[+] Loaded {len(domains)} domains from {domains_file}")
    
    # Step 1: Gather IPs from certificates and DNS
    all_ips = set()
    print(f"[+] Gathering IPs from {len(domains)} domain(s)")
    
    for i in range(0, len(domains), batch_size):
        batch = domains[i:i + batch_size]
        print(f"[+] Processing batch {i//batch_size + 1}/{(len(domains) + batch_size - 1)//batch_size}")
        
        for domain in tqdm(batch, unit="domain"):
            # Get IPs from SSL certificates
            cert_ips = passive_cert_ips(domain)
            
            # Get IPs from DNSDB if available
            dnsdb_ips_result = dnsdb_ips(domain)
            
            # Combine results
            new_ips = cert_ips | dnsdb_ips_result
            if new_ips:
                all_ips |= new_ips
                
        # Save intermediate results
        save_intermediate(all_ips, ips_file)
    
    print(f"[+] Found {len(all_ips)} unique IPs")
    
    # Step 2: Map IPs to ASNs
    asns = set()
    print("[+] Mapping IPs to ASNs")
    for ip in tqdm(all_ips, unit="ip"):
        if asn := ip_to_asn(ip):
            asns.add(asn)
            save_intermediate(asns, asns_file)
    
    print(f"[+] Found {len(asns)} unique ASNs")
    
    # Step 3: Get CIDR ranges for each ASN
    all_cidrs = set()
    print("[+] Getting CIDR ranges for ASNs")
    for asn in tqdm(asns, unit="asn"):
        cidrs = asn_prefixes(asn)
        if cidrs:
            all_cidrs |= cidrs
            save_intermediate(all_cidrs, cidrs_file)
    
    print(f"[+] Found {len(all_cidrs)} CIDR ranges")
    
    # Step 4: Filter CIDRs by company name in RDAP
    company_regex = re.compile(company_name, re.IGNORECASE)
    final_cidrs = set()
    print("[+] Filtering CIDRs by company ownership")
    for cidr in tqdm(all_cidrs, unit="cidr"):
        if org_string_in_rdap(cidr, company_regex):
            final_cidrs.add(cidr)
    
    # Save final results
    with open(output_file, 'w') as f:
        for cidr in sorted(final_cidrs):
            f.write(f"{cidr}\n")
    
    print(f"[+] Saved {len(final_cidrs)} CIDR ranges to {output_file}")
    return final_cidrs

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate IP list from company domains")
    parser.add_argument("-i", "--input", required=True, help="Input file containing domain names")
    parser.add_argument("-o", "--output", required=True, help="Output file for CIDR ranges")
    parser.add_argument("--company", required=True, help="Company name to filter results")
    parser.add_argument("--batch-size", type=int, default=50, help="Number of domains to process in each batch")
    
    args = parser.parse_args()
    get_company_ips(args.input, args.output, args.company, args.batch_size)
