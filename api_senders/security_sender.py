"""
Security sender module for sending security-related data to API endpoints.
Includes bad TLS assets, login pages, and credentials.
"""
from .base_sender import *
from urllib.parse import urlparse

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
    
    headers = get_api_headers()

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
        response = send_request_with_retry(server_url, payload, headers)
        
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
        return False
        
    if not urls:
        print("No login pages data found in file")
        return False

    # Convert URLs to the required format with structured data
    login_pages_data = []
    for url in urls:
        # Extract domain name as the name field
        try:
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
    
    headers = get_api_headers()

    # Print complete request details
    print("\nREQUEST DETAILS:")
    print(f"URL: {server_url}")
    print("\nHEADERS:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    print("\nPAYLOAD:")
    print(json.dumps(payload, indent=2))
    print(f"\nTotal login pages being sent: {len(login_pages_data)}")
    print(f"{'='*80}\n")

    # Send request
    try:
        response = send_request_with_retry(server_url, payload, headers)
        
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
        return False
        
    if not credentials_data:
        print("No credentials data found in file")
        return False

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
    
    headers = get_api_headers()

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
        response = send_request_with_retry(server_url, payload, headers)
        
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