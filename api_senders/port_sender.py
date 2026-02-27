"""
Port sender module for sending port data to API endpoints.
"""
from .base_sender import *

def send_ports_to_api(project_id, file_path='ports.txt', chunk_size=150):
    print(f"\n{'='*80}")
    print("SENDING PORTS REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    # Read ports from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            port_lines = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            port_lines = [line for line in port_lines if line]
            
            # Parse IP:PORT or DOMAIN:PORT format
            ports = []
            for line in port_lines:
                if ':' in line:
                    host, port = line.split(':', 1)  # Split only on first colon
                    ports.append({
                        'host': host.strip(),
                        'port': port.strip()
                    })
                else:
                    print(f"Warning: Skipping invalid port format: {line}")
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return False
    
    if not ports:
        print("No valid ports found in file")
        return False
    
    # Separate IP addresses from domain names for location lookup
    ip_hosts = []
    domain_hosts = []
    
    for port_info in ports:
        host = port_info['host']
        if is_valid_ip(host):
            ip_hosts.append(host)
        else:
            domain_hosts.append(host)
    
    unique_ips = list(set(ip_hosts))
    print(f"Found {len(unique_ips)} unique IP addresses and {len(set(domain_hosts))} unique domain names")
    
    # Get location data only for IP addresses
    locations = {}
    if unique_ips:
        print(f"Getting location data for {len(unique_ips)} IP addresses...")
        locations = get_bulk_location_info(unique_ips, batch_size=100)
    else:
        print("No IP addresses found for location lookup")
    
    # Prepare API request
    url = server_url + "ports.php"
    
    # Prepare batch payload with location data
    port_list = []
    for port_info in ports:
        host = port_info['host']
        
        # Get location data if host is an IP address, otherwise use defaults
        if is_valid_ip(host) and host in locations:
            location = locations[host]
        else:
            # Default location data for domain names
            location = get_default_location()
        
        port_list.append({
            "ip_address": host,  # This can be either IP or domain name
            "port": port_info['port'],
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
            "status": "open",
            "notes": f"Added via API - Project ID: {project_id}"
        })
    
    # Split ports into chunks
    total_ports = len(port_list)
    chunks = [port_list[i:i + chunk_size] for i in range(0, total_ports, chunk_size)]
    
    print(f"Total ports to send: {total_ports}")
    print(f"Chunk size: {chunk_size}")
    print(f"Number of chunks: {len(chunks)}")
    
    headers = get_api_headers()

    # Send each chunk
    successful_chunks = 0
    failed_chunks = 0
    
    for i, chunk in enumerate(chunks, 1):
        print(f"\n{'='*60}")
        print(f"SENDING CHUNK {i}/{len(chunks)} ({len(chunk)} ports)")
        print(f"{'='*60}")
        
        payload = {
            "ports": chunk
        }
        
        # Print chunk details
        print(f"Chunk {i} details:")
        print(f"URL: {url}")
        print(f"Ports in this chunk: {len(chunk)}")
        
        # Send request for this chunk
        try:
            response = send_request_with_retry(url, payload, headers)
            
            # Print response details
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code in [200, 201]:
                print(f"✅ Successfully sent chunk {i} with {len(chunk)} ports")
                successful_chunks += 1
            else:
                print(f"❌ Failed to send chunk {i}. Status code: {response.status_code}")
                failed_chunks += 1
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Request Error for chunk {i}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Error Response Status: {e.response.status_code}")
                print(f"Error Response Content: {e.response.text}")
            failed_chunks += 1
        except Exception as e:
            print(f"❌ Unexpected error for chunk {i}: {str(e)}")
            failed_chunks += 1
        
        # Add a small delay between chunks to avoid overwhelming the server
        if i < len(chunks):
            print("Waiting 1 second before next chunk...")
            time.sleep(1)
    
    print(f"\n{'='*80}")
    print("PORTS SENDING SUMMARY")
    print(f"{'='*80}")
    print(f"Total chunks: {len(chunks)}")
    print(f"Successful chunks: {successful_chunks}")
    print(f"Failed chunks: {failed_chunks}")
    print(f"Total ports sent: {successful_chunks * chunk_size}")
    print(f"Total ports failed: {failed_chunks * chunk_size}")
    
    # Return True if at least one chunk was successful
    return successful_chunks > 0


def send_sensitive_ports_to_api(project_id, file_path='sensitive_ports.txt', chunk_size=150):
    print(f"\n{'='*80}")
    print("SENDING SENSITIVE PORTS REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    # Read sensitive ports from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            port_lines = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            port_lines = [line for line in port_lines if line]
            
            # Parse IP:PORT:SERVICE format
            ports = []
            for line in port_lines:
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        port = parts[1].strip()
                        service = parts[2].strip() if len(parts) > 2 else "unknown"
                        ports.append({
                            'ip': ip,
                            'port': port,
                            'service': service
                        })
                else:
                    print(f"Warning: Skipping invalid port format: {line}")
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return False
        
    if not ports:
        print("No valid sensitive ports found in file")
        return False
    
    # Extract unique IPs for location lookup
    unique_ips = list(set([port_info['ip'] for port_info in ports]))
    print(f"Getting location data for {len(unique_ips)} unique IPs...")
    
    # Get location data for all IPs in bulk
    locations = get_bulk_location_info(unique_ips, batch_size=100)
    
    # Prepare API request
    url = server_url + "ports.php?bulk=1"
    
    # Prepare batch payload with location data
    port_list = []
    for port_info in ports:
        ip = port_info['ip']
        location = locations.get(ip, get_default_location())
        
        port_list.append({
            "ip_address": ip,
            "port": port_info['port'],
            "is_sensitive": True,
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
            "status": "open",
            "service": port_info['service']
        })
    
    # Split ports into chunks
    total_ports = len(port_list)
    chunks = [port_list[i:i + chunk_size] for i in range(0, total_ports, chunk_size)]
    
    print(f"Total sensitive ports to send: {total_ports}")
    print(f"Chunk size: {chunk_size}")
    print(f"Number of chunks: {len(chunks)}")
    
    headers = get_api_headers()

    # Send each chunk
    successful_chunks = 0
    failed_chunks = 0
    
    for i, chunk in enumerate(chunks, 1):
        print(f"\n{'='*60}")
        print(f"SENDING SENSITIVE PORTS CHUNK {i}/{len(chunks)} ({len(chunk)} ports)")
        print(f"{'='*60}")
        
        payload = {
            "ports": chunk
        }
        
        # Print chunk details
        print(f"Chunk {i} details:")
        print(f"URL: {url}")
        print(f"Sensitive ports in this chunk: {len(chunk)}")
        
        # Send request for this chunk
        try:
            response = requests.put(url, headers=headers, json=payload, verify=False)
            
            # Print response details
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code in [200, 201]:
                print(f"✅ Successfully sent sensitive ports chunk {i} with {len(chunk)} ports")
                successful_chunks += 1
            else:
                print(f"❌ Failed to send sensitive ports chunk {i}. Status code: {response.status_code}")
                failed_chunks += 1
        
        except requests.exceptions.RequestException as e:
            print(f"❌ Request Error for sensitive ports chunk {i}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Error Response Status: {e.response.status_code}")
                print(f"Error Response Content: {e.response.text}")
            failed_chunks += 1
        except Exception as e:
            print(f"❌ Unexpected error for sensitive ports chunk {i}: {str(e)}")
            failed_chunks += 1
        
        # Add a small delay between chunks to avoid overwhelming the server
        if i < len(chunks):
            print("Waiting 1 second before next chunk...")
            time.sleep(1)
    
    print(f"\n{'='*80}")
    print("SENSITIVE PORTS SENDING SUMMARY")
    print(f"{'='*80}")
    print(f"Total chunks: {len(chunks)}")
    print(f"Successful chunks: {successful_chunks}")
    print(f"Failed chunks: {failed_chunks}")
    print(f"Total sensitive ports sent: {successful_chunks * chunk_size}")
    print(f"Total sensitive ports failed: {failed_chunks * chunk_size}")
    
    # Return True if at least one chunk was successful
    return successful_chunks > 0 