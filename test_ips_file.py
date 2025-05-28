from ip_location import get_location_info, get_bulk_location_info
import os

def test_ips_from_file(file_path='ips.txt'):
    print("\nTesting IPs from file:", file_path)
    
    try:
        # Read IPs from file
        with open(file_path, 'r') as file:
            ips = [line.strip() for line in file.readlines()]
            ips = [ip for ip in ips if ip]  # Remove empty lines

        if not ips:
            print("No IPs found in file")
            return

        print(f"\nProcessing {len(ips)} IPs from {file_path}")
        
        # Get location data for all IPs in bulk
        print("Getting location data for all IPs...")
        locations = get_bulk_location_info(ips, batch_size=50)  # Process in batches of 10
        
        # Process each IP with its location data
        for ip in ips:
            print(f"\nTesting IP: {ip}")
            print("-" * 30)
            
            if ip in locations:
                location = locations[ip]
                print("\nLocation Information:")
                print(f"  Country: {location.get('country_name', 'Unknown')} ({location.get('country_code', 'UN')})")
                print(f"  Region: {location.get('region', 'Unknown')}")
                print(f"  City: {location.get('city', 'Unknown')}")
                print(f"  Coordinates: {location.get('latitude')}, {location.get('longitude')}")
                print(f"  Continent: {location.get('continent', 'Unknown')} ({location.get('continent_code', 'UN')})")
                print("\nNetwork Information:")
                print(f"  ISP: {location.get('isp', 'Unknown')}")
                print(f"  Organization: {location.get('org', 'Unknown')}")
                print(f"  ASN: {location.get('asn', 'Unknown')}")
                print(f"  ASN Name: {location.get('asn_name', 'Unknown')}")
            else:
                print("No location data available for this IP")
            
            print("-" * 30)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_ips_from_file() 