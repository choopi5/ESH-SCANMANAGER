from ip_location import get_location_info

def test_ip_location():
    # Test IPs with known locations
    test_ips = [
        # IPv4 addresses
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "208.67.222.222", # OpenDNS
        "192.168.1.1",  # Private IP
        "127.0.0.1",    # Localhost
        # IPv6 addresses
        "2001:4860:4860::8888",  # Google DNS IPv6
        "2606:4700:4700::1111",  # Cloudflare DNS IPv6
        "fe80::1",               # Link-local
        "::1",                   # IPv6 localhost
        "2001:db8::1"           # Documentation address
    ]

    print("\nTesting IP Location Lookup")
    print("=" * 50)

    for ip in test_ips:
        print(f"\nTesting IP: {ip}")
        print("-" * 30)
        
        location = get_location_info(ip)
        
        print(f"Country Code: {location['country_code']}")
        print(f"Country Name: {location['country_name']}")
        print(f"City: {location['city']}")
        print(f"Region: {location['region']}")
        print(f"Latitude: {location['latitude']}")
        print(f"Longitude: {location['longitude']}")

if __name__ == "__main__":
    test_ip_location() 