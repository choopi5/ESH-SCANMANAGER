"""
Domain sender module for sending subdomain and alive domain data to API endpoints.
"""
from .base_sender import *

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
    
    headers = get_api_headers()

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
        response = send_request_with_retry(url, payload, headers)
        
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
    
    headers = get_api_headers()

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
        response = send_request_with_retry(url, payload, headers)
        
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