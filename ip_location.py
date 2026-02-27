import os
import requests
import ipaddress
import time
import json
import config
# import socket  # Not needed - SOCKS proxy disabled

# SOCKS proxy disabled - not required anymore
# try:
#     import socks
#     
#     # Set up SOCKS proxy if not already configured
#     if not hasattr(socks, '_orgsocket'):
#         print(f"Info: Configuring SOCKS proxy {config.PROXY_HOST}:{config.PROXY_PORT}")
#         socks.set_default_proxy(socks.SOCKS5, config.PROXY_HOST, config.PROXY_PORT)
#         socket.socket = socks.socksocket
#     
#     print(f"Info: Testing SOCKS proxy connectivity to {config.PROXY_HOST}:{config.PROXY_PORT}...")
#     
#     # Test if proxy is reachable - REQUIRED for operation
#     test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     test_socket.settimeout(5)  # 5 second timeout
#     try:
#         test_socket.connect((config.PROXY_HOST, config.PROXY_PORT))
#         test_socket.close()
#         print(f"✓ SOCKS proxy {config.PROXY_HOST}:{config.PROXY_PORT} is reachable - proceeding")
#     except (ConnectionRefusedError, OSError, socket.timeout) as e:
#         print(f"✗ CRITICAL: SOCKS proxy {config.PROXY_HOST}:{config.PROXY_PORT} is not reachable: {e}")
#         print("  SOCKS proxy is required for operation. Please ensure your proxy server is running.")
#         raise ConnectionError(f"Required SOCKS proxy {config.PROXY_HOST}:{config.PROXY_PORT} is not available")
#         
# except ImportError:
#     print("✗ CRITICAL: SOCKS module not available but required for operation")
#     print("  Please install with: pip install PySocks")
#     raise ImportError("PySocks module is required but not installed")
# except Exception as e:
#     print(f"✗ CRITICAL: Failed to configure SOCKS proxy: {e}")
#     raise

# Using ipwhois.pro bulk API for geolocation

def is_private_ip(ip):
    """Check if an IP address is private/local"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def is_valid_ip(ip):
    """Check if the string is a valid IPv4 or IPv6 address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_bulk_location_info_ipwhois(ip_list, batch_size=100):
    """Get location info using ipwhois.io bulk API - exact format from documentation"""
    print(f"📡 Using ipwhois.pro bulk API for {len(ip_list)} IPs...")
    
    results = {}
    default_response = {
        "country_code": "UN",
        "country_name": "Unknown", 
        "city": "Unknown",
        "region": "Unknown",
        "latitude": None,
        "longitude": None,
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "asn_name": "Unknown",
        "continent": "Unknown",
        "continent_code": "UN"
    }
    
    # Process in batches (up to 100 IPs per request as per documentation)
    total_batches = (len(ip_list) + batch_size - 1) // batch_size
    
    for i in range(0, len(ip_list), batch_size):
        batch = ip_list[i:i+batch_size]
        current_batch = i//batch_size + 1
        print(f"📦 Processing batch {current_batch}/{total_batches}: {len(batch)} IPs")
        
        try:
            # ipwhois.pro bulk endpoint - exact format from documentation
            endpoint = f"{config.IPWHOIS_BULK_URL}?key={config.IPWHOIS_API_KEY}"
            
            response = requests.post(
                endpoint,
                json=batch,  # Send IP array directly as JSON body
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Response should be an array of IP data objects
                if isinstance(data, list):
                    for ip_data in data:
                        ip = ip_data.get("ip", "")
                        if ip and ip_data.get("success", True):
                            # Extract connection data
                            connection = ip_data.get("connection", {})
                            
                            results[ip] = {
                                "country_code": ip_data.get("country_code", "UN"),
                                "country_name": ip_data.get("country", "Unknown"),
                                "city": ip_data.get("city", "Unknown"),
                                "region": ip_data.get("region", "Unknown"),
                                "latitude": ip_data.get("latitude"),
                                "longitude": ip_data.get("longitude"),
                                "isp": connection.get("isp", "Unknown"),
                                "org": connection.get("org", "Unknown"),
                                "asn": str(connection.get("asn", "Unknown")),
                                "asn_name": connection.get("org", "Unknown"),
                                "continent": ip_data.get("continent", "Unknown"),
                                "continent_code": ip_data.get("continent_code", "UN")
                            }
                        else:
                            if ip:
                                results[ip] = default_response.copy()
                            
                elif isinstance(data, dict) and not data.get("success", True):
                    # Handle API error response
                    print(f"⚠ API error: {data.get('message', 'Unknown error')}")
                    for ip in batch:
                        results[ip] = default_response.copy()
                else:
                    print(f"⚠ Unexpected response format: {type(data)}")
                    for ip in batch:
                        results[ip] = default_response.copy()
                        
                print(f"✓ Successfully processed batch {current_batch}/{total_batches}: {len(batch)} IPs")
                
                # Show sample of what was retrieved in this batch
                if batch and results:
                    sample_ip = batch[0]
                    sample_data = results.get(sample_ip, {})
                    if sample_data and sample_data.get('city') != 'Unknown':
                        print(f"📋 Sample geolocation from batch {current_batch}:")
                        print(f"   IP: {sample_ip}")
                        print(f"   Location: {sample_data.get('city', 'Unknown')}, {sample_data.get('region', 'Unknown')}, {sample_data.get('country_name', 'Unknown')}")
                        print(f"   ISP: {sample_data.get('isp', 'Unknown')}")
                        print(f"   Coordinates: {sample_data.get('latitude', 'N/A')}, {sample_data.get('longitude', 'N/A')}")
            else:
                print(f"⚠ Batch {current_batch}/{total_batches} failed with status {response.status_code}")
                print(f"Response: {response.text[:200]}...")
                # Add default responses for failed batch
                for ip in batch:
                    results[ip] = default_response.copy()
                    
            # Small delay between batches to be respectful
            if i + batch_size < len(ip_list):
                time.sleep(1)
                
        except Exception as e:
            print(f"⚠ Error processing batch {current_batch}/{total_batches}: {e}")
            # Add default responses for failed batch
            for ip in batch:
                results[ip] = default_response.copy()
    
    return results

def get_bulk_location_info(ip_list, batch_size=100):
    """
    TRUE BULK location lookup using ipwhois.pro paid API
    """
    results = {}
    default_response = {
        "country_code": "UN",
        "country_name": "Unknown",
        "city": "Unknown", 
        "region": "Unknown",
        "latitude": None,
        "longitude": None,
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "asn_name": "Unknown",
        "continent": "Unknown",
        "continent_code": "UN"
    }

    # Filter out invalid and private IPs
    valid_ips = []
    for ip in ip_list:
        if is_valid_ip(ip) and not is_private_ip(ip):
            valid_ips.append(ip)
        else:
            results[ip] = default_response.copy()
            if not is_valid_ip(ip):
                print(f"Warning: Invalid IP address format: {ip}")
            else:
                print(f"Info: IP {ip} is private/local - using default location")

    if not valid_ips:
        print("No valid public IPs to process")
        return results

    print(f"🚀 BULK PROCESSING {len(valid_ips)} public IPs using ipwhois.pro bulk API...")
    
    # Use ipwhois.pro bulk API (includes excellent city data)
    api_results = get_bulk_location_info_ipwhois(valid_ips, batch_size)
    results.update(api_results)
    
    print(f"✅ Bulk processing complete: {len(results)} total IPs processed")
    return results

def get_location_info(ip):
    """Get location info for a single IP (uses bulk function for consistency)"""
    bulk_result = get_bulk_location_info([ip], batch_size=1)
    return bulk_result.get(ip, {
        "country_code": "UN",
        "country_name": "Unknown",
        "city": "Unknown",
        "region": "Unknown", 
        "latitude": None,
        "longitude": None,
        "isp": "Unknown",
        "org": "Unknown",
        "asn": "Unknown",
        "asn_name": "Unknown",
        "continent": "Unknown",
        "continent_code": "UN"
    }) 