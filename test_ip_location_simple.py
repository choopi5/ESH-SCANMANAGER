#!/usr/bin/env python3
"""
Simple test script to verify IP location lookup is working correctly
"""

from ip_location import get_location_info, get_bulk_location_info

def test_single_ip():
    """Test single IP lookup"""
    print("="*60)
    print("TESTING SINGLE IP LOOKUP")
    print("="*60)
    
    test_ips = [
        "8.8.8.8",  # Google DNS (should be hardcoded)
        "1.1.1.1",  # Cloudflare DNS (should be hardcoded)
        "13.107.42.14",  # Microsoft IP
        "151.101.193.140"  # Reddit IP
    ]
    
    for ip in test_ips:
        print(f"\nTesting IP: {ip}")
        result = get_location_info(ip)
        print(f"Country: {result['country_name']} ({result['country_code']})")
        print(f"City: {result['city']}")
        print(f"ISP: {result['isp']}")
        print(f"ASN: {result['asn']}")

def test_bulk_lookup():
    """Test bulk IP lookup"""
    print("\n" + "="*60)
    print("TESTING BULK IP LOOKUP")
    print("="*60)
    
    test_ips = [
        "13.107.42.14",  # Microsoft
        "151.101.193.140",  # Reddit
        "172.217.164.110"  # Google
    ]
    
    print(f"\nTesting bulk lookup with {len(test_ips)} IPs...")
    results = get_bulk_location_info(test_ips)
    
    print(f"\nResults:")
    for ip, data in results.items():
        print(f"\nIP: {ip}")
        print(f"  Country: {data['country_name']} ({data['country_code']})")
        print(f"  City: {data['city']}")
        print(f"  ISP: {data['isp']}")
        print(f"  ASN: {data['asn']}")

if __name__ == "__main__":
    test_single_ip()
    test_bulk_lookup()
    
    print("\n" + "="*60)
    print("TEST COMPLETE")
    print("="*60) 