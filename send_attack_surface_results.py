import requests
import json
import urllib3
import os
import sys
import subprocess
import socks
import socket
from ip_location import get_location_info, get_bulk_location_info
import time
from config import API_BASE_URL, API_KEY, PROXY_HOST, PROXY_PORT
from datetime import datetime
from pathlib import Path
import re
from modules.utils import parse_ips_from_file
from enrich_vulnerabilities import normalize_severity


# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure SOCKS5 proxy
socks.set_default_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
socket.socket = socks.socksocket

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
        return
        
    ip_records = cache_data.get('ip_records', [])
    project_id = cache_data.get('project_id')
    
    if not ip_records:
        print("❌ No IP records found in cache")
        return
        
    # Prepare the API request
    server_url = f"{API_BASE_URL}ip_addresses.php"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY
    }

    # Send cached records with progress tracking
    total = len(ip_records)
    batch_size = 50
    total_batches = (total + batch_size - 1) // batch_size
    
    print(f"\n🚀 Resuming API submission: {total_batches} batches of up to {batch_size} IPs each")
    
    for i in range(0, total, batch_size):
        batch = ip_records[i:i+batch_size]
        current_batch = i//batch_size + 1
        payload = {"ip_addresses": batch}
        
        print(f"\n📤 Sending batch {current_batch}/{total_batches} ({len(batch)} IPs) [{(current_batch/total_batches)*100:.1f}%]")
        
        # Show sample record from this batch
        if batch:
            sample_record = batch[0]
            print(f"📋 Sample record from batch {current_batch}:")
            print(f"   IP: {sample_record.get('ip_address', 'N/A')}")
            print(f"   Location: {sample_record.get('city', 'N/A')}, {sample_record.get('region', 'N/A')}, {sample_record.get('country_name', 'N/A')}")
            print(f"   ISP: {sample_record.get('isp', 'N/A')}")
            print(f"   Coordinates: {sample_record.get('latitude', 'N/A')}, {sample_record.get('longitude', 'N/A')}")
        
        try:
            response = requests.post(server_url, headers=headers, json=payload, verify=False)
            print(f"Status Code: {response.status_code}")
            print(f"Response Body: {response.text}")
            
            if response.status_code in [200, 201]:
                print(f"✅ Batch {current_batch}/{total_batches} sent successfully")
            else:
                print(f"⚠ Batch {current_batch}/{total_batches} failed with status {response.status_code}")
                
        except Exception as e:
            print(f"❌ Error sending batch {current_batch}/{total_batches}: {e}")
            
        # Small delay between batches
        time.sleep(1)
    
    print(f"\n🎉 Completed sending all {total_batches} batches from cache!")

def send_ips_to_api(project_id, file_path='ips.txt'):
    # Get absolute path if relative path is provided
    file_path = os.path.abspath(file_path)
    
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
            headers = {
                "Content-Type": "application/json",
                "X-API-Key": API_KEY
            }

            # Send cached records with progress tracking
            total = len(ip_records)
            batch_size = 50
            total_batches = (total + batch_size - 1) // batch_size
            
            print(f"\n🚀 Resuming API submission: {total_batches} batches of up to {batch_size} IPs each")
            
            for i in range(0, total, batch_size):
                batch = ip_records[i:i+batch_size]
                current_batch = i//batch_size + 1
                payload = {"ip_addresses": batch}
                
                print(f"\n📤 Sending batch {current_batch}/{total_batches} ({len(batch)} IPs) [{(current_batch/total_batches)*100:.1f}%]")
                
                # Show sample record from this batch
                if batch:
                    sample_record = batch[0]
                    print(f"📋 Sample record from batch {current_batch}:")
                    print(f"   IP: {sample_record.get('ip_address', 'N/A')}")
                    print(f"   Location: {sample_record.get('city', 'N/A')}, {sample_record.get('region', 'N/A')}, {sample_record.get('country_name', 'N/A')}")
                    print(f"   ISP: {sample_record.get('isp', 'N/A')}")
                    print(f"   Coordinates: {sample_record.get('latitude', 'N/A')}, {sample_record.get('longitude', 'N/A')}")
                
                try:
                    response = requests.post(server_url, headers=headers, json=payload, verify=False)
                    print(f"Status Code: {response.status_code}")
                    print(f"Response Body: {response.text}")
                    
                    if response.status_code in [200, 201]:
                        print(f"✅ Batch {current_batch}/{total_batches} sent successfully")
                    else:
                        print(f"⚠ Batch {current_batch}/{total_batches} failed with status {response.status_code}")
                        
                except Exception as e:
                    print(f"❌ Error sending batch {current_batch}/{total_batches}: {e}")
                    
                time.sleep(1)
            
            print(f"\n🎉 Completed sending all {total_batches} batches from cache!")
            
            # Clean up cache file after successful completion
            try:
                os.remove(cache_file)
                print(f"🗑️ Cleaned up cache file: {cache_name}")
            except Exception as e:
                print(f"⚠ Could not remove cache file: {e}")
            
            return  # Exit early since we used cached data

    try:
        # Parse IPs from file using shared utility function
        parse_result = parse_ips_from_file(file_path)
        ips = parse_result['ips']
        skipped_lines = parse_result['skipped_lines']
        stats = parse_result['stats']
        
        # Report parsing results
        if skipped_lines:
            print(f"Warning: Skipped {stats['skipped_lines']} lines that couldn't be parsed as IPs:")
            for line in skipped_lines[:5]:  # Show first 5 examples
                print(f"  - {line}")
            if len(skipped_lines) > 5:
                print(f"  ... and {len(skipped_lines) - 5} more")

        if not ips:
            print("No valid IPs found in file after parsing")
            return

        print(f"\nProcessing {stats['extracted_ips']} IPs extracted from {stats['total_lines']} lines in {file_path}")
        print(f"IP extraction rate: {stats['extraction_rate']:.1f}%")
        
        # Get location data for all IPs in bulk
        print("Getting location data for all IPs...")
        locations = get_bulk_location_info(ips, batch_size=100)  # Optimized: use max batch size per documentation
        
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

        # Save IP records to cache file before sending (for resume capability)
        print(f"💾 Saving IP records cache to: {cache_name}")
        
        try:
            cache_data = {
                'ip_records': ip_records,
                'total_batches': (len(ip_records) + 49) // 50,  # Calculate total batches
                'batch_size': 50,
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
            batch = ip_records[i:i+batch_size]
            current_batch = i//batch_size + 1
            payload = {"ip_addresses": batch}
            
            print(f"\n📤 Sending batch {current_batch}/{total_batches} ({len(batch)} IPs) [{(current_batch/total_batches)*100:.1f}%]")
            
            # Show sample record from this batch
            if batch:
                sample_record = batch[0]
                print(f"📋 Sample record from batch {current_batch}:")
                print(f"   IP: {sample_record.get('ip_address', 'N/A')}")
                print(f"   Location: {sample_record.get('city', 'N/A')}, {sample_record.get('region', 'N/A')}, {sample_record.get('country_name', 'N/A')}")
                print(f"   ISP: {sample_record.get('isp', 'N/A')}")
                print(f"   Coordinates: {sample_record.get('latitude', 'N/A')}, {sample_record.get('longitude', 'N/A')}")
            
            print(f"URL: {server_url}")
            print("Payload:", json.dumps(payload, indent=2))
            
            try:
                response = requests.post(server_url, headers=headers, json=payload, verify=False)
                print(f"Status Code: {response.status_code}")
                print(f"Response Body: {response.text}")
                
                # Log successful batch
                if response.status_code in [200, 201]:
                    print(f"✅ Batch {current_batch}/{total_batches} sent successfully")
                else:
                    print(f"⚠ Batch {current_batch}/{total_batches} failed with status {response.status_code}")
                    
            except Exception as e:
                print(f"❌ Error sending batch {current_batch}/{total_batches}: {e}")
                
            # Small delay between batches
            time.sleep(1)

        print(f"\n🎉 Completed sending all {total_batches} batches!")
        
        # Clean up cache file after successful completion
        try:
            os.remove(cache_file)
            print(f"🗑️ Cleaned up cache file: {cache_name}")
        except Exception as e:
            print(f"⚠ Could not remove cache file: {e}")
        
        return True

    except Exception as e:
        print(f"❌ Error during processing: {e}")
        print(f"💾 IP records are cached in: {cache_name}")
        print(f"🔄 To resume, use: send_cached_ips_to_api('{cache_file}')")
        return False

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
        return False
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
            return True
        else:
            print(f"Failed to send ports. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

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
        return False
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
            return True
        else:
            print(f"Failed to send subdomains. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

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
        return False
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
            return True
        else:
            print(f"Failed to send APIs. Status code: {response.status_code}")
            return False    
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
        return False
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
            return True
        else:
            print(f"Failed to update alive domains. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

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
        return False
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
            return True
        else:
            print(f"Failed to send sensitive ports. Status code: {response.status_code}")
            return False    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_vulnerabilities_to_api(project_id, file_path='enriched_vulnerabilities.json'):
    """Send vulnerabilities to the API"""
    print(f"\n{'='*80}")
    print("SENDING VULNERABILITIES REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = API_BASE_URL
    
    # Read vulnerabilities from file
    try:
        with open(abs_file_path, 'r') as file:
            vulnerabilities = json.load(file)
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return False
    # Prepare API request
    url = server_url + "vulnerabilities.php"
    
    # Prepare batch payload
    vuln_list = []
    for vuln in vulnerabilities:
        # Determine endpoint type and value
        endpoint_type = "subdomain"  # Default to subdomain
        endpoint_value = vuln.get('host', '')  # Get host from vulnerability data
        
        # If no host, try to get from other possible fields
        if not endpoint_value:
            endpoint_value = vuln.get('target', '')
        if not endpoint_value:
            endpoint_value = vuln.get('domain', '')
        if not endpoint_value:
            endpoint_value = vuln.get('ip', '')
            
        # If still no endpoint value, skip this vulnerability
        if not endpoint_value:
            print(f"Warning: Skipping vulnerability {vuln.get('name', 'Unknown')} - No endpoint value found")
            continue
        
        # If target is an IP address, change endpoint type
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', endpoint_value):
            endpoint_type = "ip"
        
        vuln_list.append({
            "name": vuln.get('name', ''),
            "cve_id": vuln.get('cve_id', ''),
            "severity": normalize_severity(vuln.get('severity', 'Unknown')),
            "status": "Active",  # Default status
            "description": vuln.get('description', ''),
            "remediation": vuln.get('remediation', ''),
            "discovery_date": vuln.get('discovery_date', datetime.now().strftime('%Y-%m-%d')),
            "organization_id": project_id,
            "notes": f"Added via API - Project ID: {project_id}",
            "endpoint_type": endpoint_type,
            "endpoint_value": endpoint_value
        })
    
    if not vuln_list:
        print("No valid vulnerabilities to send (all were skipped due to missing endpoint values)")
        return
        
    payload = {
        "vulnerabilities": vuln_list
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
    print(f"\nTotal vulnerabilities being sent: {len(vuln_list)}")
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
            print(f"Successfully sent {len(vuln_list)} vulnerabilities to API")
            return True
        else:
            print(f"Failed to send vulnerabilities. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print("\n❌ Connection Error!")
        print(f"Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response Status: {e.response.status_code}")
            print(f"Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Response Content: {e.response.text}")
    except Exception as e:
        print("\n❌ Unexpected Error!")
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e)}")
    
    except requests.exceptions.RequestException as e:
        print("\n❌ Connection Error!")
        print(f"Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response Status: {e.response.status_code}")
            print(f"Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Response Content: {e.response.text}")
    except Exception as e:
        print("\n❌ Unexpected Error!")
        print(f"Error: {str(e)}")
        print(f"Error type: {type(e)}")

def send_bad_tls_assets_to_api(project_id, file_path='bad_tls_assets.txt'):
    """Send Bad TLS Assets findings to the API"""
    print(f"\n{'='*80}")
    print("SENDING BAD TLS ASSETS REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = f"{API_BASE_URL}bad_tls_assets.php"
    
    # Read Bad TLS Assets findings from file
    try:
        with open(abs_file_path, 'r') as file:
            findings_lines = [line.strip() for line in file.readlines() if line.strip()]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return False
    if not findings_lines:
        print("No findings data found in file")
        return False

    # Parse findings into structured format
    findings = []
    for line in findings_lines:
        try:
            # Parse format: https://hostname:port [finding-type] details
            if line.startswith('https://') or line.startswith('http://'):
                # Extract URL and port
                url_part = line.split(' ')[0]
                protocol, rest = url_part.split('://')
                hostname_port = rest.split('/')[0]
                
                if ':' in hostname_port:
                    hostname, port = hostname_port.split(':')
                else:
                    hostname = hostname_port
                    port = 443 if protocol == 'https' else 80
                
                # Extract IP address from hostname if it contains IP-like segments
                ip_address = None
                print(f"DEBUG: Processing hostname: {hostname}")
                if hostname.startswith('ip-'):
                    print(f"DEBUG: Found IP-like hostname: {hostname}")
                    # Extract IP from format: ip-216-176-61-1.berkeleypayment.com
                    ip_part = hostname.split('.')[0]  # ip-216-176-61-1
                    print(f"DEBUG: IP part: {ip_part}")
                    if ip_part.startswith('ip-'):
                        ip_str = ip_part[3:]  # 216-176-61-1
                        ip_address = ip_str.replace('-', '.')  # 216.176.61.1
                        print(f"DEBUG: Extracted IP: {ip_address}")
                        # Extract the actual domain name
                        domain_parts = hostname.split('.')
                        if len(domain_parts) > 1:
                            hostname = '.'.join(domain_parts[1:])  # berkeleypayment.com
                            print(f"DEBUG: Cleaned hostname: {hostname}")
                else:
                    print(f"DEBUG: Regular hostname, no IP extraction needed")
                
                # Extract finding type and details
                remaining = line[len(url_part):].strip()
                if remaining.startswith('[') and ']' in remaining:
                    finding_type_end = remaining.find(']')
                    finding_type = remaining[1:finding_type_end]
                    details = remaining[finding_type_end + 1:].strip()
                else:
                    finding_type = "tls-issue"
                    details = remaining
                
                finding_data = {
                    "hostname": hostname,
                    "finding_type": finding_type,
                    "severity": "low",
                    "port": int(port),
                    "organization_id": project_id,
                    "details": details,
                    "risk_score": 0
                }
                
                # Add IP address if we extracted one
                if ip_address:
                    finding_data["ip_address"] = ip_address
                
                findings.append(finding_data)
        except Exception as e:
            print(f"Warning: Could not parse line: {line} - {e}")
            continue

    if not findings:
        print("No valid findings could be parsed from file")
        return False

    # Prepare API request with structured data
    payload = {
        "findings": findings
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {server_url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal findings to send: {len(findings)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(server_url, headers=headers, json=payload, verify=False)
        
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
            print(f"Successfully sent Bad TLS Assets findings to API")
            return True
        else:
            print(f"Failed to send Bad TLS Assets findings. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

def send_login_pages_to_api(project_id, file_path='login_pages.txt'):
    """Send Login Pages data to the API"""
    print(f"\n{'='*80}")
    print("SENDING LOGIN PAGES REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = f"{API_BASE_URL}login_pages"
    
    # Read Login Pages data from file (one URL per line)
    try:
        with open(abs_file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return
        return False
    if not urls:
        print("No login pages data found in file")
        return

    # Convert URLs to the required format with structured data
    login_pages_data = []
    for url in urls:
        # Extract domain name as the name field
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            name = parsed.netloc or parsed.path
        except:
            name = url
        
        login_pages_data.append({
            "name": name,
            "url": url,
            "organization_id": project_id
        })

    # Prepare API request
    payload = {
        "login_pages": login_pages_data
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {server_url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal login pages being sent: {len(login_pages_data) if isinstance(login_pages_data, list) else 1}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(server_url, headers=headers, json=payload, verify=False)
        
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
            print(f"Successfully sent Login Pages data to API")
            return True
        else:
            print(f"Failed to send Login Pages data. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False

def send_credentials_to_api(project_id, file_path='credentials.txt', breach_source=None, breach_date=None):
    """Send Credentials data to the API"""
    print(f"\n{'='*80}")
    print("SENDING CREDENTIALS REQUEST")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided
    abs_file_path = os.path.abspath(file_path)
    server_url = f"{API_BASE_URL}credentials"
    
    # Read Credentials data from file
    try:
        with open(abs_file_path, 'r') as file:
            credentials_data = file.read().strip()
    except Exception as e:
        print(f"Error reading file {abs_file_path}: {e}")
        return
        return False
    if not credentials_data:
        print("No credentials data found in file")
        return

    # Prepare API request with structured data
    payload = {
        "credentials": [
            {
                "data": credentials_data,
                "organization_id": project_id,
                "breach_source": breach_source if breach_source else None,
                "breach_date": breach_date if breach_date else None
            }
        ]
    }
    
    headers = {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {server_url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal credentials data length: {len(credentials_data)} characters")
    if breach_source:
        print(f"Breach source: {breach_source}")
    if breach_date:
        print(f"Breach date: {breach_date}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = requests.post(server_url, headers=headers, json=payload, verify=False)
        
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
            print(f"Successfully sent Credentials data to API")
            return True
        else:
            print(f"Failed to send Credentials data. Status code: {response.status_code}")
            return False
    
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Error Response Status: {e.response.status_code}")
            print(f"Error Response Headers: {json.dumps(dict(e.response.headers), indent=2)}")
            print(f"Error Response Content: {e.response.text}")
        return False
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        print(f"Error type: {type(e)}")
        return False


def send_credentials_file_to_api(project_id, file_path='credentials.txt', breach_source=None, breach_date=None):
    """
    Send credentials file to the API using multipart form data
    """
    try:
        # Check if file exists
        if not os.path.exists(file_path):
            print(f"⚠️  Credentials file not found: {file_path}")
            return False
        
        # Check if file is empty
        if os.path.getsize(file_path) == 0:
            print(f"⚠️  Credentials file is empty, skipping...")
            return False

        # Prepare multipart form data
        files = {
            'credentials_file': (os.path.basename(file_path), open(file_path, 'rb'), 'text/plain')
        }
        
        data = {
            'project_id': str(project_id)
        }
        
        # Add optional fields if provided
        if breach_source:
            data['breach_source'] = breach_source
        if breach_date:
            data['breach_date'] = breach_date
        
        headers = {
            'X-API-Key': API_KEY
        }

        server_url = "https://100.20.158.40/api/routes/credentials"
        
        print(f"📤 Sending credentials file to: {server_url}")
        print(f"📁 File: {file_path}")
        print(f"📊 File size: {os.path.getsize(file_path)} bytes")
        print(f"📋 Form data: {data}")
        print(f"📁 Files: {list(files.keys())}")
        
        response = requests.post(server_url, files=files, data=data, headers=headers, verify=False)
        
        print(f"📊 Response Status: {response.status_code}")
        print(f"📄 Response Headers: {dict(response.headers)}")
        print(f"📝 Response Text: {response.text}")
        
        if response.status_code in [200, 201]:
            print(f"✅ Successfully sent credentials file to API")
            return True
        else:
            print(f"❌ Failed to send credentials file. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except FileNotFoundError:
        print(f"⚠️  Credentials file not found: {file_path}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error sending credentials file: {e}")
        return False
    except Exception as e:
        print(f"❌ Error sending credentials file: {e}")
        return False


def create_or_update_organization(project_id, domain_name):
    """
    Create or update organization record in the database
    """
    try:
        # Clean the domain name to proper naming convention
        # Remove www. prefix and get the TLD
        if domain_name.startswith('www.'):
            domain_name = domain_name[4:]
        
        # Extract the main domain (remove subdomains)
        domain_parts = domain_name.split('.')
        if len(domain_parts) >= 2:
            # Get the last two parts for TLD (e.g., example.com)
            domain_tld = '.'.join(domain_parts[-2:])
        else:
            domain_tld = domain_name
        
        # Prepare the organization data
        org_data = {
            "id": project_id,
            "name": domain_name,
            "domain": domain_tld,
            "subscription_plan": "basic",  # Default plan
            "active": True
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': API_KEY
        }

        # Try to create new organization
        server_url = f"{API_BASE_URL}organizations"
        
        print(f"📤 Creating/updating organization: {domain_tld}")
        print(f"📊 Organization data: {org_data}")
        
        response = requests.post(server_url, json=org_data, headers=headers, verify=False)
        
        print(f"📊 Response Status: {response.status_code}")
        print(f"📝 Response Text: {response.text}")
        
        if response.status_code in [200, 201]:
            print(f"✅ Successfully created/updated organization: {domain_tld}")
            return True
        else:
            print(f"❌ Failed to create/update organization. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error creating organization: {e}")
        return False
    except Exception as e:
        print(f"❌ Error creating organization: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Send attack surface results to API')
    parser.add_argument('project_id', type=int, help='Project ID')
    parser.add_argument('folder_path', help='Path to folder containing scan results')
    parser.add_argument('--fields', nargs='+', choices=[
        'ips', 'ports', 'sensitive_ports', 'subdomains', 'apis', 
        'alive', 'vulnerabilities', 'bad_tls_assets', 'login_pages', 'credentials'
    ], help='Specific fields to send (default: all available fields)')
    parser.add_argument('--org-only', action='store_true', help='Only create/update organization, skip attack surface data')
    
    args = parser.parse_args()
    
    project_id = args.project_id
    folder_path = args.folder_path
    selected_fields = args.fields
    
    # Extract project name from folder path (last part)
    project_name = os.path.basename(folder_path.rstrip('/\\'))
    
    print(f"📁 Project: {project_name}")
    print(f"🆔 Project ID: {project_id}")
    print(f"📂 Folder: {folder_path}")
    
    # Create or update organization record
    print(f"\n🏢 Creating/updating organization record...")
    org_success = create_or_update_organization(project_id, project_name)
    if not org_success:
        print(f"⚠️  Warning: Failed to create/update organization record, but continuing with attack surface...")
    
    # If --org-only flag is set, exit after organization creation
    if args.org_only:
        if org_success:
            print(f"✅ Organization creation completed successfully!")
            sys.exit(0)
        else:
            print(f"❌ Organization creation failed!")
            sys.exit(1)
    
    # Get the project name from the last part of the folder path
    path_parts = Path(folder_path).parts
    project_name = path_parts[-1] if path_parts else "unknown_project"
    
    print(f"Project name extracted: {project_name}")
    
    # Run nuclei analyzer first (optional)
    print(f"\n{'='*80}")
    print("RUNNING NUCLEI ANALYSIS")
    print(f"{'='*80}")
    
    nuclei_success = False
    try:
        # Check if nuclei analyzer script exists
        nuclei_script = 'nuclei_results_analyzer.py'
        if os.path.exists(nuclei_script):
            # Run the nuclei analyzer with the full folder path
            result = subprocess.run([
                sys.executable, nuclei_script, folder_path
            ], capture_output=True, text=True, cwd=os.getcwd())
            
            print("Nuclei Analyzer Output:")
            print(result.stdout)
            
            if result.stderr:
                print("Nuclei Analyzer Errors:")
                print(result.stderr)
            
            if result.returncode == 0:
                print("✅ Nuclei analysis completed successfully")
                nuclei_success = True
            else:
                print(f"⚠ Nuclei analysis completed with return code: {result.returncode}")
        else:
            print("⚠ Nuclei analyzer script not found, skipping nuclei analysis")
            
    except Exception as e:
        print(f"❌ Error running nuclei analyzer: {e}")
        print("⚠ Continuing without nuclei analysis...")
    
    print(f"{'='*80}\n")

    # Construct file paths
    ips_file = os.path.join(folder_path, './leads/ips.txt')
    ports_file = os.path.join(folder_path, './leads/ports.txt')
    sensitive_ports_file = os.path.join(folder_path, './findings/sensitive_ports.txt')
    subdomains_file = os.path.join(folder_path, './leads/subdomains.txt')
    apis_file = os.path.join(folder_path, './leads/api.txt')
    alive_file = os.path.join(folder_path, './leads/alive.txt')
    vulnerabilities_file = os.path.join(folder_path, './findings/enriched_vulnerabilities.json')
    
    # New API endpoints file paths
    bad_tls_assets_file = os.path.join(folder_path, './findings/bad_tls_assets.txt')
    login_pages_file = os.path.join(folder_path, './leads/login_pages.txt')
    credentials_file = os.path.join(folder_path, './findings/credentials.txt')

    # Define field mappings
    field_mappings = {
        'ips': (ips_file, "IP addresses"),
        'ports': (ports_file, "Ports"),
        'sensitive_ports': (sensitive_ports_file, "Sensitive ports"),
        'subdomains': (subdomains_file, "Subdomains"),
        'apis': (apis_file, "APIs"),
        'alive': (alive_file, "Alive domains"),
        'vulnerabilities': (vulnerabilities_file, "Vulnerabilities"),
        'bad_tls_assets': (bad_tls_assets_file, "Bad TLS Assets"),
        'login_pages': (login_pages_file, "Login Pages"),
        'credentials': (credentials_file, "Credentials")
    }
    
    # Check if required files exist before proceeding
    print(f"\n{'='*80}")
    print("CHECKING FILES")
    print(f"{'='*80}")
    
    if selected_fields:
        print(f"Selected fields to send: {', '.join(selected_fields)}")
        files_to_check = [(field_mappings[field][0], field_mappings[field][1]) for field in selected_fields if field in field_mappings]
    else:
        print("No specific fields selected - will send all available files")
        # Define which files are required vs optional when sending all
        required_fields = ['ips', 'ports', 'sensitive_ports', 'subdomains', 'apis', 'alive', 'vulnerabilities', 'bad_tls_assets', 'login_pages']
        optional_fields = ['credentials']
        
        files_to_check = [(field_mappings[field][0], field_mappings[field][1]) for field in required_fields + optional_fields if field in field_mappings]
    
    missing_files = []
    existing_files = []
    
    # Check files
    for file_path, description in files_to_check:
        if os.path.exists(file_path):
            existing_files.append((file_path, description))
            print(f"✅ {description}: {file_path}")
        else:
            missing_files.append((file_path, description))
            print(f"❌ {description}: {file_path}")
    
    if not existing_files:
        print(f"\n❌ No files found to send. Exiting.")
        sys.exit(1)
    
    if selected_fields and missing_files:
        print(f"\n❌ Missing required files for selected fields. Cannot proceed:")
        for file_path, description in missing_files:
            print(f"   - {description}: {file_path}")
        print(f"\n❌ All selected field files must be present before sending. Exiting.")
        sys.exit(1)
    elif not selected_fields and any(f[1] in ["IP addresses", "Ports", "Sensitive ports", "Subdomains", "APIs", "Alive domains", "Vulnerabilities", "Bad TLS Assets", "Login Pages"] for f in missing_files):
        print(f"\n❌ Missing required files. Cannot proceed:")
        for file_path, description in missing_files:
            if description in ["IP addresses", "Ports", "Sensitive ports", "Subdomains", "APIs", "Alive domains", "Vulnerabilities", "Bad TLS Assets", "Login Pages"]:
                print(f"   - {description}: {file_path}")
        print(f"\n❌ All required files must be present before sending. Exiting.")
        sys.exit(1)
    
    print(f"\n{'='*80}")
    print("SENDING DATA TO APIs")
    print(f"{'='*80}")
    
    if selected_fields:
        print(f"📤 Sending only selected fields: {', '.join(selected_fields)}")
    else:
        print(f"📤 Sending all available fields")
    
    # Track results for summary
    results = {
        'success': [],
        'failed': [],
        'skipped': []
    }
    
    # Send data from each existing file
    for file_path, description in existing_files:
        print(f"\n📤 Sending {description}...")
        
        try:
            if description == "IP addresses":
                success = send_ips_to_api(project_id, file_path)
            elif description == "Ports":
                success = send_ports_to_api(project_id, file_path)
            elif description == "Sensitive ports":
                success = send_sensitive_ports_to_api(project_id, file_path)
            elif description == "Subdomains":
                success = send_subdomains_to_api(project_id, file_path)
            elif description == "APIs":
                success = send_apis_to_api(project_id, file_path)
            elif description == "Alive domains":
                success = send_alive_to_api(project_id, file_path)
            elif description == "Vulnerabilities":
                success = send_vulnerabilities_to_api(project_id, file_path)
            elif description == "Bad TLS Assets":
                success = send_bad_tls_assets_to_api(project_id, file_path)
            elif description == "Login Pages":
                success = send_login_pages_to_api(project_id, file_path)
            elif description == "Credentials":
                success = send_credentials_file_to_api(project_id, file_path)
            else:
                success = False
                print(f"❌ Unknown field type: {description}")
            
            if success:
                results['success'].append(description)
            else:
                results['failed'].append(description)
                
        except Exception as e:
            print(f"❌ Exception occurred while sending {description}: {e}")
            results['failed'].append(description)
    
    # Print final summary report
    print(f"\n{'='*80}")
    print("FINAL SUMMARY REPORT")
    print(f"{'='*80}")
    
    total_attempted = len(results['success']) + len(results['failed']) + len(results['skipped'])
    total_success = len(results['success'])
    total_failed = len(results['failed'])
    total_skipped = len(results['skipped'])
    
    print(f"📊 OVERALL RESULTS:")
    print(f"   Total attempted: {total_attempted}")
    print(f"   ✅ Successful: {total_success}")
    print(f"   ❌ Failed: {total_failed}")
    print(f"   ⏭️  Skipped: {total_skipped}")
    
    if total_attempted > 0:
        success_rate = (total_success / total_attempted) * 100
        print(f"   📈 Success rate: {success_rate:.1f}%")
    
    if results['success']:
        print(f"\n✅ SUCCESSFUL OPERATIONS:")
        for item in results['success']:
            print(f"   • {item}")
    
    if results['failed']:
        print(f"\n❌ FAILED OPERATIONS:")
        for item in results['failed']:
            print(f"   • {item}")
    
    if results['skipped']:
        print(f"\n⏭️  SKIPPED OPERATIONS:")
        for item in results['skipped']:
            print(f"   • {item}")
    
    print(f"\n{'='*80}")
    
    if total_failed > 0:
        print(f"⚠️  {total_failed} operation(s) failed. Please check the logs above for details.")
        sys.exit(1)
    else:
        print(f"🎉 All operations completed successfully!") 