import requests
import json
import urllib3
import os
import sys
import socks
import socket
from ip_location import get_location_info, get_bulk_location_info
import time
from config import API_BASE_URL, API_KEY, PROXY_HOST, PROXY_PORT

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure SOCKS5 proxy
socks.set_default_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
socket.socket = socks.socksocket

def send_ips_to_api(project_id, file_path='ips.txt'):
    # Get absolute path if relative path is provided
    file_path = os.path.abspath(file_path)
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return

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
        locations = get_bulk_location_info(ips, batch_size=50)  # Use batch size of 50 for lookup as well
        
        # Prepare the list of IP data dicts
        ip_records = []
        for ip in ips:
            location = locations.get(ip, {})
            ip_data = {
                "ip_address": ip,
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
                "notes": f"Added via bulk API"
            }
            ip_records.append(ip_data)

        if not ip_records:
            print("No IPs to send")
            return

        # Prepare the API request
        server_url = f"{API_BASE_URL}ip_addresses.php"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY
        }

        # Send in bulks of 50
        total = len(ip_records)
        batch_size = 50
        for i in range(0, total, batch_size):
            batch = ip_records[i:i+batch_size]
            payload = {"ip_addresses": batch}
            print(f"\nSending batch {i//batch_size+1} ({len(batch)} IPs)...")
            print(f"URL: {server_url}")
            print("Payload:", json.dumps(payload, indent=2))
            response = requests.post(server_url, headers=headers, json=payload, verify=False)
            print("Status Code:", response.status_code)
            print("Response Body:", response.text)
            # Optional: add a small delay between batches
            time.sleep(1)

    except Exception as e:
        print(f"Error: {e}")

def send_ports_to_api(project_id, file_path='ports.txt'):
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
            
            # Parse IP:PORT format
            ports = []
            for line in port_lines:
                if ':' in line:
                    ip, port = line.split(':')
                    ports.append({
                        'ip': ip.strip(),
                        'port': port.strip()
                    })
                else:
                    print(f"Warning: Skipping invalid port format: {line}")
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return

    # Prepare API request
    url = server_url + "ports.php"
    
    # Prepare batch payload
    port_list = []
    for port_info in ports:
        port_list.append({
            "ip_address": port_info['ip'],
            "port": port_info['port'],
            "organization_id": project_id,
            "status": "open",
            "notes": f"Added via API - Project ID: {project_id}"
        })
    
    payload = {
        "ports": port_list
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal ports being sent: {len(port_list)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        
        # Print response details
        print("\nRESPONSE DETAILS:")
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        print("\nResponse Body:")
        print(response.text)
        print(f"{'='*80}\n")
        
        if response.status_code in [200, 201]:
            print(f"Successfully sent {len(port_list)} ports to API")
        else:
            print(f"Failed to send ports. Status code: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_subdomains_to_api(project_id, file_path='subdomains.txt'):
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    print(f"\n{'='*80}")
    print("SENDING SUBDOMAINS REQUEST")
    print(f"{'='*80}")
    
    # Read subdomains from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            subdomains = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            subdomains = [subdomain for subdomain in subdomains if subdomain]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return

    # Read alive domains to filter out
    alive_domains = set()
    alive_file = os.path.join(os.path.dirname(abs_file_path), 'alive.txt')
    if os.path.exists(alive_file):
        try:
            with open(alive_file, 'r') as file:
                # Read lines and strip whitespace
                alive_domains = {line.strip().replace('http://', '').replace('https://', '') for line in file.readlines()}
                # Remove any empty lines
                alive_domains = {domain for domain in alive_domains if domain}
        except Exception as e:
            print(f"Warning: Error reading alive file {alive_file}: {e}")

    # Filter out subdomains that are already in alive
    new_subdomains = [subdomain for subdomain in subdomains if subdomain not in alive_domains]
    
    if not new_subdomains:
        print("No new subdomains to send (all are already in alive list)")
        return

    # Prepare API request
    url = server_url + "subdomains.php"
    
    # Prepare batch payload
    subdomain_list = []
    for subdomain in new_subdomains:
        subdomain_list.append({
            "subdomain_name": subdomain,
            "organization_id": project_id,
            "status": "dns-only",
            "notes": f"Added via API - Project ID: {project_id}"
        })
    
    payload = {
        "subdomains": subdomain_list
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal new subdomains being sent: {len(subdomain_list)}")
    print(f"Filtered out {len(subdomains) - len(new_subdomains)} subdomains that were already in alive list")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        
        # Print response details
        print("\nRESPONSE DETAILS:")
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        print("\nResponse Body:")
        print(response.text)
        print(f"{'='*80}\n")
        
        if response.status_code in [200, 201]:
            print(f"Successfully sent {len(subdomain_list)} new subdomains to API")
        else:
            print(f"Failed to send subdomains. Status code: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_apis_to_api(project_id, file_path='api.txt'):
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    print(f"\n{'='*80}")
    print("SENDING APIS REQUEST")
    print(f"{'='*80}")
    
    # Read APIs from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            apis = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            apis = [api for api in apis if api]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return

    # Prepare API request
    url = server_url + "api_endpoints.php"
    
    # Prepare batch payload
    api_list = []
    for api in apis:
        api_list.append({
            "api": api,
            "organization_id": project_id,
            "status": "active",
            "notes": f"Added via API - Project ID: {project_id}"
        })
    
    payload = {
        "apis": api_list
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal APIs being sent: {len(api_list)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        
        # Print response details
        print("\nRESPONSE DETAILS:")
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        print("\nResponse Body:")
        print(response.text)
        print(f"{'='*80}\n")
        
        if response.status_code in [200, 201]:
            print(f"Successfully sent {len(api_list)} APIs to API")
        else:
            print(f"Failed to send APIs. Status code: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_alive_to_api(project_id, file_path='alive.txt'):
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    print(f"\n{'='*80}")
    print("SENDING ALIVE REQUEST")
    print(f"{'='*80}")
    
    # Read alive domains from file
    try:
        with open(abs_file_path, 'r') as file:
            # Read lines and strip whitespace
            alive_domains = [line.strip() for line in file.readlines()]
            # Remove any empty lines
            alive_domains = [domain for domain in alive_domains if domain]
            # Remove http:// and https:// prefixes
            alive_domains = [domain.replace('http://', '').replace('https://', '') for domain in alive_domains]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return

    # Prepare API request
    url = server_url + "subdomains.php"
    
    # Prepare batch payload
    alive_list = []
    for domain in alive_domains:
        alive_list.append({
            "subdomain_name": domain,
            "organization_id": project_id,
            "status": "active",
            "notes": f"Added via API - Project ID: {project_id}"
        })
    
    payload = {
        "subdomains": alive_list
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal alive domains being sent: {len(alive_list)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        
        # Print response details
        print("\nRESPONSE DETAILS:")
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        print("\nResponse Body:")
        print(response.text)
        print(f"{'='*80}\n")
        
        if response.status_code in [200, 201]:
            print(f"Successfully updated {len(alive_list)} alive domains to API")
        else:
            print(f"Failed to update alive domains. Status code: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_sensitive_ports_to_api(project_id, file_path='sensitive_ports.txt'):
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
        return

    # Prepare API request
    url = server_url + "ports.php?bulk=1"
    
    # Prepare batch payload
    port_list = []
    for port_info in ports:
        port_list.append({
            "ip_address": port_info['ip'],
            "port": port_info['port'],
            "is_sensitive": True,
            "organization_id": project_id,
            "status": "open",
            "service": port_info['service']
        })
    
    payload = {
        "ports": port_list
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal sensitive ports being sent: {len(port_list)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.put(url, headers=headers, json=payload, verify=False)
        
        # Print response details
        print("\nRESPONSE DETAILS:")
        print(f"Status Code: {response.status_code}")
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        print("\nResponse Body:")
        print(response.text)
        print(f"{'='*80}\n")
        
        if response.status_code in [200, 201]:
            print(f"Successfully sent {len(port_list)} sensitive ports to API")
        else:
            print(f"Failed to send sensitive ports. Status code: {response.status_code}")
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

if __name__ == "__main__":
    # Check if both project_id and folder path are provided
    if len(sys.argv) != 3:
        print("Usage: python send_attack_surface.py <project_id> <folder_path>")
        sys.exit(1)

    project_id = int(sys.argv[1])
    folder_path = sys.argv[2]

    # Construct file paths
    ips_file = os.path.join(folder_path, './Data/ips.txt')
    ports_file = os.path.join(folder_path, './Data/ports.txt')
    sensitive_ports_file = os.path.join(folder_path, './Data/sensitive_ports.txt')
    subdomains_file = os.path.join(folder_path, './Data/subdomains.txt')
    apis_file = os.path.join(folder_path, './Data/api.txt')
    alive_file = os.path.join(folder_path, './Data/alive.txt')

    # Send data from each file
    if os.path.exists(ips_file):
        #send_ips_to_api(project_id, ips_file)
        i=5;
    else:
        print(f"Warning: {ips_file} not found")

    if os.path.exists(ports_file):
        send_ports_to_api(project_id, ports_file)
        i=5;
    else:
        print(f"Warning: {ports_file} not found")

    if os.path.exists(sensitive_ports_file):
        send_sensitive_ports_to_api(project_id, sensitive_ports_file)
        i=5;
    else:
        print(f"Warning: {sensitive_ports_file} not found")

    if os.path.exists(subdomains_file):
        #send_subdomains_to_api(project_id, subdomains_file)
        i=5;
    else:
        print(f"Warning: {subdomains_file} not found")

    if os.path.exists(apis_file):
        #send_apis_to_api(project_id, apis_file)
        i=5;
    else:
        print(f"Warning: {apis_file} not found")

    if os.path.exists(alive_file):
        #send_alive_to_api(project_id, alive_file)
        i=5;
    else:
        print(f"Warning: {alive_file} not found") 