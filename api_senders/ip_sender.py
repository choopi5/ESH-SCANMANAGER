"""
IP sender module for sending IP address data to API endpoints.
"""
from .base_sender import *

def resume_ips_from_cache(cache_file):
    """Resume IP processing from a cache file"""
    if not os.path.exists(cache_file):
        print(f"❌ Cache file not found: {cache_file}")
        return None
        
    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
            
        print(f"📋 Found cache file: {cache_file}")
        print(f"   Original source: {cache_data.get('source_file', 'Unknown')}")
        print(f"   Cached at: {cache_data.get('timestamp', 'Unknown')}")
        print(f"   Total IP records: {len(cache_data.get('ip_records', []))}")
        print(f"   Total batches: {cache_data.get('total_batches', 'Unknown')}")
        
        return cache_data
        
    except Exception as e:
        print(f"❌ Error reading cache file: {e}")
        return None

def send_cached_ips_to_api(cache_file):
    """Send IPs to API from a cached file (resume functionality)"""
    cache_data = resume_ips_from_cache(cache_file)
    if not cache_data:
        return False
        
    ip_records = cache_data.get('ip_records', [])
    project_id = cache_data.get('project_id')
    
    if not ip_records:
        print("❌ No IP records found in cache")
        return False
        
    # Prepare the API request
    server_url = f"{API_BASE_URL}ip_addresses.php"
    headers = get_api_headers()

    # Send cached records with progress tracking
    total = len(ip_records)
    batch_size = 50
    total_batches = (total + batch_size - 1) // batch_size
    
    print(f"\n🚀 Resuming API submission: {total_batches} batches of up to {batch_size} IPs each")
    
    for i in range(0, total, batch_size):
        batch = ip_records[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        
        print(f"\n📤 Sending batch {batch_num}/{total_batches} ({len(batch)} IPs) [{(batch_num/total_batches)*100:.1f}%]")
        
        # Sample record for verification
        if batch:
            sample = batch[0]
            print(f"📋 Sample record from batch {batch_num}:")
            print(f"   IP: {sample.get('ip_address', 'Unknown')}")
            if sample.get('hostname'):
                print(f"   Hostname: {sample.get('hostname')}")
            print(f"   Location: {sample.get('city', 'Unknown')}, {sample.get('region', 'Unknown')}, {sample.get('country_name', 'Unknown')}")
            print(f"   ISP: {sample.get('isp', 'Unknown')}")
            print(f"   Coordinates: {sample.get('latitude', 'N/A')}, {sample.get('longitude', 'N/A')}")
        
        payload = {"ips": batch}
        
        try:
            response = send_request_with_retry(server_url, payload, headers)
            print(f"Status Code: {response.status_code}")
            print(f"Response Body: {response.text}")
            
            if response.status_code in [200, 201]:
                print(f"✅ Batch {batch_num}/{total_batches} sent successfully")
            else:
                print(f"❌ Batch {batch_num}/{total_batches} failed with status {response.status_code}")
        except Exception as e:
            print(f"❌ Error sending batch {batch_num}: {e}")
    
    print(f"\n🎉 Completed sending all {total_batches} batches from cache!")
    
    # Clean up cache file after successful completion
    try:
        os.remove(cache_file)
        print(f"🗑️ Cleaned up cache file: {cache_name}")
    except Exception as e:
        print(f"⚠ Could not remove cache file: {e}")
    
    return True  # Exit early since we used cached data successfully

    

def send_ips_to_api(project_id, file_path='ips.txt'):
    # Get absolute path if relative path is provided
    
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return False
    # Generate cache file path in same folder as source file
    file_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    cache_name = file_name.replace('.txt', '_ip_records_cache.json')
    cache_file = os.path.join(file_dir, cache_name)
    
    # Check for existing cache file and auto-resume
    if os.path.exists(cache_file):
        print(f"\n🔄 Found existing cache file: {cache_name}")
        cache_data = resume_ips_from_cache(cache_file)
        if cache_data and cache_data.get('ip_records'):
            print(f"✅ Auto-resuming: {len(cache_data['ip_records'])} IP records ready to send")
            print(f"📁 Cache location: {cache_file}")
            
            # Directly use cached data for API sending
            ip_records = cache_data.get('ip_records', [])
            
            # Prepare the API request
            server_url = f"{API_BASE_URL}ip_addresses.php"
            headers = get_api_headers()

            # Send cached records with progress tracking
            total = len(ip_records)
            batch_size = 50
            total_batches = (total + batch_size - 1) // batch_size
            
            print(f"\n🚀 Resuming API submission: {total_batches} batches of up to {batch_size} IPs each")
            
            for i in range(0, total, batch_size):
                batch = ip_records[i:i + batch_size]
                batch_num = (i // batch_size) + 1
                
                print(f"\n📤 Sending batch {batch_num}/{total_batches} ({len(batch)} IPs) [{(batch_num/total_batches)*100:.1f}%]")
                
                # Sample record for verification
                if batch:
                    sample = batch[0]
                    print(f"📋 Sample record from batch {batch_num}:")
                    print(f"   IP: {sample.get('ip_address', 'Unknown')}")
                    if sample.get('hostname'):
                        print(f"   Hostname: {sample.get('hostname')}")
                    print(f"   Location: {sample.get('city', 'Unknown')}, {sample.get('region', 'Unknown')}, {sample.get('country_name', 'Unknown')}")
                    print(f"   ISP: {sample.get('isp', 'Unknown')}")
                    print(f"   Coordinates: {sample.get('latitude', 'N/A')}, {sample.get('longitude', 'N/A')}")
                
                payload = {"ip_addresses": batch}
                
                try:
                    response = send_request_with_retry(server_url, payload, headers)
                    print(f"Status Code: {response.status_code}")
                    print(f"Response Body: {response.text}")
                    
                    if response.status_code in [200, 201]:
                        print(f"✅ Batch {batch_num}/{total_batches} sent successfully")
                    else:
                        print(f"❌ Batch {batch_num}/{total_batches} failed with status {response.status_code}")
                except Exception as e:
                    print(f"❌ Error sending batch {batch_num}: {e}")
            
            print(f"\n🎉 Completed sending all {total_batches} batches from cache!")
            
            # Clean up cache file after successful completion
            try:
                os.remove(cache_file)
                print(f"🗑️ Cleaned up cache file: {cache_name}")
            except Exception as e:
                print(f"⚠ Could not remove cache file: {e}")
            
            return True  # Exit early since we used cached data successfully

    try:
        # Parse IPs from file using enhanced utility function with hostname support
        parse_result = parse_ips_from_file(file_path, include_hostname=True)
        ip_hostname_data = parse_result['ips']  # Now contains dicts with 'ip' and 'hostname'
        skipped_lines = parse_result['skipped_lines']
        stats = parse_result['stats']
        
        # Report parsing results
        if skipped_lines:
            print(f"Warning: Skipped {stats['skipped_lines']} lines that couldn't be parsed as IPs:")
            for line in skipped_lines[:5]:  # Show first 5 examples
                print(f"  - {line}")
            if len(skipped_lines) > 5:
                print(f"  ... and {len(skipped_lines) - 5} more")

        if not ip_hostname_data:
            print("No valid IPs found in file after parsing")
            return False

        # Extract just the IPs for geolocation lookup
        ips = [item['ip'] for item in ip_hostname_data]
        
        print(f"\nProcessing {stats['extracted_ips']} IPs extracted from {stats['total_lines']} lines in {file_path}")
        print(f"IP extraction rate: {stats['extraction_rate']:.1f}%")
        
        # Count how many have hostnames
        with_hostname = sum(1 for item in ip_hostname_data if item.get('hostname'))
        print(f"Found hostnames for {with_hostname} IPs ({(with_hostname/len(ip_hostname_data)*100):.1f}%)")
        
        # Get location data for all IPs in bulk
        print("Getting location data for all IPs...")
        locations = get_bulk_location_info(ips, batch_size=100)  # Optimized: use max batch size per documentation
        
        # Prepare the list of IP data dicts with hostname support
        ip_records = []
        for item in ip_hostname_data:
            ip = item['ip']
            hostname = item.get('hostname')
            location = locations.get(ip, {})
            
            ip_data = {
                "ip_address": ip,
                "hostname": hostname,  # Include hostname field
                "country_code": location.get("country_code", "UN"),
                "country_name": location.get("country_name", "Unknown"),
                "city": location.get("city", "Unknown"),
                "region": location.get("region", "Unknown"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "isp": location.get("isp", "Unknown"),
                "org": location.get("org", "Unknown"),
                "asn": location.get("asn", "Unknown"),
                "asn_name": location.get("asn_name", "Unknown"),
                "continent": location.get("continent", "Unknown"),
                "continent_code": location.get("continent_code", "UN"),
                "organization_id": project_id,
                "status": "active",
                "notes": f"Added via bulk API{' with hostname' if hostname else ''}"
            }
            ip_records.append(ip_data)

        if not ip_records:
            print("No IPs to send")
            return False

        # Prepare the API request
        server_url = f"{API_BASE_URL}ip_addresses.php"
        headers = get_api_headers()

        # Save IP records to cache file before sending (for resume capability)
        print(f"💾 Saving IP records cache to: {cache_name}")
        
        try:
            batch_size = 50  # Define batch_size for cache metadata
            cache_data = {
                'ip_records': ip_records,
                'total_batches': (len(ip_records) + batch_size - 1) // batch_size,  # Calculate total batches
                'batch_size': batch_size,
                'timestamp': datetime.now().isoformat(),
                'project_id': project_id,
                'source_file': file_path
            }
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2, default=str)
            print(f"✅ Cached {len(ip_records)} IP records for safe processing")
        except Exception as e:
            print(f"⚠ Warning: Could not save cache: {e}")

        # Send in bulks of 50 with progress tracking
        total = len(ip_records)
        batch_size = 50
        total_batches = (total + batch_size - 1) // batch_size
        
        print(f"\n🚀 Starting API submission: {total_batches} batches of up to {batch_size} IPs each")
        
        for i in range(0, total, batch_size):
            batch = ip_records[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            
            print(f"\n📤 Sending batch {batch_num}/{total_batches} ({len(batch)} IPs) [{(batch_num/total_batches)*100:.1f}%]")
            
            # Sample record for verification
            if batch:
                sample = batch[0]
                print(f"📋 Sample record from batch {batch_num}:")
                print(f"   IP: {sample.get('ip_address', 'Unknown')}")
                if sample.get('hostname'):
                    print(f"   Hostname: {sample.get('hostname')}")
                print(f"   Location: {sample.get('city', 'Unknown')}, {sample.get('region', 'Unknown')}, {sample.get('country_name', 'Unknown')}")
                print(f"   ISP: {sample.get('isp', 'Unknown')}")
                print(f"   Coordinates: {sample.get('latitude', 'N/A')}, {sample.get('longitude', 'N/A')}")
            
            payload = {"ip_addresses": batch}
            
            try:
                response = send_request_with_retry(server_url, payload, headers)
                print(f"Status Code: {response.status_code}")
                print(f"Response Body: {response.text}")
                
                if response.status_code in [200, 201]:
                    print(f"✅ Batch {batch_num}/{total_batches} sent successfully")
                else:
                    print(f"❌ Batch {batch_num}/{total_batches} failed with status {response.status_code}")
            except Exception as e:
                print(f"❌ Error sending batch {batch_num}: {e}")
        
        print(f"\n🎉 Completed sending all {total_batches} batches!")
        
        # Clean up cache file after successful completion
        try:
            os.remove(cache_file)
            print(f"🗑️ Cleaned up cache file: {cache_name}")
        except Exception as e:
            print(f"⚠ Could not remove cache file: {e}")
        
        return True  # Successfully completed all operations
        
    except Exception as e:
        print(f"Error processing IPs: {e}")
        return False 