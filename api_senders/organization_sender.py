"""
Organization sender module for creating and managing organizations.
"""
from .base_sender import *

def create_organization(project_id, domain_name):
    """
    Create a new organization using the provided project_id as organization_id.
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
        
        # Add current timestamp to the name for multiple runs (includes time for uniqueness)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        org_name_with_timestamp = f"{domain_name}_{timestamp}"
        
        # Prepare the organization data - use project_id as organization_id
        org_data = {
            "organization_id": project_id,  # Use the provided project_id directly
            "name": org_name_with_timestamp,
            "domain": domain_tld,
            "subscription_plan": "basic",
            "active": True
        }
        
        headers = get_api_headers()

        # Create new organization
        server_url = f"{API_BASE_URL}organizations.php"
        
        print(f"[+] Creating new organization: {org_name_with_timestamp}")
        print(f"[*] Organization data: {org_data}")
        
        response = send_request_with_retry(server_url, org_data, headers)
        
        print(f"[*] Response Status: {response.status_code}")
        print(f"[*] Response Text: {response.text}")
        
        if response.status_code in [200, 201]:
            print(f"[+] Successfully created new organization: {org_name_with_timestamp} with ID: {project_id}")
            return True
        else:
            print(f"[-] Failed to create organization. Status code: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error creating organization: {e}")
        return False
    except Exception as e:
        print(f"[-] Error creating organization: {e}")
        return False 