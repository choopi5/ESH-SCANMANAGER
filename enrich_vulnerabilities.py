import json
import requests
from pathlib import Path
import os
from datetime import datetime
import time
import sys
from config import NVD_API_KEY

def get_nvd_api_key():
    """Get NVD API key from config or environment variable"""
    try:
        if NVD_API_KEY:
            return NVD_API_KEY
    except ImportError:
        pass
    
    # Try environment variable
    api_key = os.getenv('NVD_API_KEY')
    if api_key:
        return api_key
        
    return None

def normalize_severity(severity):
    """Normalize severity to proper case for API compatibility"""
    if not severity:
        return "Unknown"
    
    severity_lower = severity.lower()
    if severity_lower in ['critical']:
        return "Critical"
    elif severity_lower in ['high']:
        return "High"
    elif severity_lower in ['medium']:
        return "Medium"
    elif severity_lower in ['low']:
        return "Low"
    else:
        return "Unknown"

def calculate_severity_from_cvss(cvss_v3_score=None, cvss_v2_score=None):
    """Calculate severity based on CVSS scores"""
    # Prefer CVSS v3 if available
    if cvss_v3_score is not None:
        score = cvss_v3_score
    elif cvss_v2_score is not None:
        score = cvss_v2_score
    else:
        return "Unknown"
    
    # Convert score to severity (proper case to match API requirements)
    if score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def get_nvd_data(cve_id, api_key=None, max_retries=3, retry_delay=5):
    """Fetch CVE data from NVD API with retry logic"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {
        "Content-Type": "application/json"
    }
    
    if api_key:
        headers["apiKey"] = api_key
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 403:
                if attempt < max_retries - 1:
                    print(f"Rate limit hit, waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                    continue
                else:
                    print(f"Error: Rate limit exceeded after {max_retries} attempts")
                    return None
                    
            response.raise_for_status()
            data = response.json()
            
            if not data.get('vulnerabilities'):
                return None
                
            vuln = data['vulnerabilities'][0]['cve']
            
            # Extract CVSS scores
            cvss_v3 = None
            cvss_v2 = None
            if 'metrics' in vuln:
                if 'cvssMetricV31' in vuln['metrics']:
                    cvss_v3 = vuln['metrics']['cvssMetricV31'][0]['cvssData']
                if 'cvssMetricV2' in vuln['metrics']:
                    cvss_v2 = vuln['metrics']['cvssMetricV2'][0]['cvssData']
            
            # Get severity from CVSS v3 if available, otherwise v2
            severity = None
            if cvss_v3:
                severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
            elif cvss_v2:
                severity = cvss_v2.get('baseSeverity', 'UNKNOWN')
            
            # If severity is unknown, calculate it from CVSS scores
            if severity == 'UNKNOWN':
                severity = calculate_severity_from_cvss(
                    cvss_v3.get('baseScore') if cvss_v3 else None,
                    cvss_v2.get('baseScore') if cvss_v2 else None
                )
            
            # Normalize severity to proper case
            severity = normalize_severity(severity)
            
            # Get description
            description = None
            if 'descriptions' in vuln:
                for desc in vuln['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
            
            return {
                'name': vuln['id'],
                'cve_id': vuln['id'],
                'severity': severity,
                'status': vuln.get('vulnStatus', 'UNKNOWN'),
                'description': description,
                'remediation': 'No remediation information available',
                'discovery_date': vuln.get('published', ''),
                'created_at': vuln.get('published', ''),
                'updated_at': vuln.get('lastModified', ''),
                'cvss_v3_score': cvss_v3.get('baseScore') if cvss_v3 else None,
                'cvss_v2_score': cvss_v2.get('baseScore') if cvss_v2 else None,
                'cvss_v3_vector': cvss_v3.get('vectorString') if cvss_v3 else None,
                'cvss_v2_vector': cvss_v2.get('vectorString') if cvss_v2 else None
            }
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                print(f"Error fetching {cve_id} (attempt {attempt + 1}/{max_retries}): {str(e)}")
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print(f"Failed to fetch {cve_id} after {max_retries} attempts: {str(e)}")
                return None
        except Exception as e:
            print(f"Unexpected error fetching {cve_id}: {str(e)}")
            return None

def get_nvd_data_bulk(cve_ids, api_key=None):
    """Fetch multiple CVE data from NVD API in bulk"""
    # Join CVEs with commas for bulk request
    cve_string = ','.join(cve_ids)
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_string}"
    headers = {
        "Content-Type": "application/json"
    }
    
    if api_key:
        headers["apiKey"] = api_key
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if not data.get('vulnerabilities'):
            return {}
            
        # Create a dictionary of CVE data
        results = {}
        for vuln in data['vulnerabilities']:
            cve = vuln['cve']
            cve_id = cve['id']
            
            # Extract CVSS scores
            cvss_v3 = None
            cvss_v2 = None
            if 'metrics' in cve:
                if 'cvssMetricV31' in cve['metrics']:
                    cvss_v3 = cve['metrics']['cvssMetricV31'][0]['cvssData']
                if 'cvssMetricV2' in cve['metrics']:
                    cvss_v2 = cve['metrics']['cvssMetricV2'][0]['cvssData']
            
            # Get severity from CVSS v3 if available, otherwise v2
            severity = None
            if cvss_v3:
                severity = cvss_v3.get('baseSeverity', 'UNKNOWN')
            elif cvss_v2:
                severity = cvss_v2.get('baseSeverity', 'UNKNOWN')
            
            # Normalize severity to proper case
            severity = normalize_severity(severity)
            
            # Get description
            description = None
            if 'descriptions' in cve:
                for desc in cve['descriptions']:
                    if desc['lang'] == 'en':
                        description = desc['value']
                        break
            
            results[cve_id] = {
                'name': cve_id,
                'cve_id': cve_id,
                'severity': severity,
                'status': cve.get('vulnStatus', 'UNKNOWN'),
                'description': description,
                'remediation': 'No remediation information available',
                'discovery_date': cve.get('published', ''),
                'created_at': cve.get('published', ''),
                'updated_at': cve.get('lastModified', ''),
                'cvss_v3_score': cvss_v3.get('baseScore') if cvss_v3 else None,
                'cvss_v2_score': cvss_v2.get('baseScore') if cvss_v2 else None,
                'cvss_v3_vector': cvss_v3.get('vectorString') if cvss_v3 else None,
                'cvss_v2_vector': cvss_v2.get('vectorString') if cvss_v2 else None
            }
        
        return results
    except Exception as e:
        print(f"Error fetching bulk data: {str(e)}")
        return {}

def process_vulnerabilities(input_file, output_file, organization_id):
    """Process vulnerabilities and enrich with NVD data"""
    try:
        # Get API key if available
        api_key = get_nvd_api_key()
        if api_key:
            print("API key found - using higher rate limits")
        else:
            print("No API key found - using standard rate limits")
        
        # Read input file
        with open(input_file, 'r') as f:
            vulnerabilities = json.load(f)
        
        # Count total CVEs to process
        total_cves = sum(len(vuln['data']['cves']) for vuln in vulnerabilities if vuln['subtype'] == 'cve')
        processed_cves = 0
        enriched_vulns = []
        failed_cves = []
        
        # Cache for CVE data to prevent redundant API calls
        cve_cache = {}
        
        print(f"\nFound {total_cves} CVEs to process")
        
        # First pass: collect all unique CVEs
        unique_cves = set()
        for vuln in vulnerabilities:
            if vuln['subtype'] == 'cve':
                unique_cves.update(vuln['data']['cves'])
        
        # Fetch all unique CVEs first
        print(f"\nFetching {len(unique_cves)} unique CVEs...")
        for cve in unique_cves:
            if cve not in cve_cache:
                print(f"\rFetching CVE: {cve}", end='')
                nvd_data = get_nvd_data(cve, api_key)
                if nvd_data:
                    cve_cache[cve] = nvd_data
                else:
                    failed_cves.append(cve)
                time.sleep(0.6 if api_key else 6)
        
        print("\n\nProcessing vulnerabilities...")
        # Second pass: process all vulnerabilities using cached data
        for vuln in vulnerabilities:
            if vuln['subtype'] == 'cve':
                for cve in vuln['data']['cves']:
                    processed_cves += 1
                    print(f"\rProcessing {processed_cves}/{total_cves}: {cve}", end='')
                    
                    if cve in cve_cache:
                        # Create a copy of the cached data
                        vuln_data = cve_cache[cve].copy()
                        vuln_data['organization_id'] = organization_id
                        vuln_data['host'] = vuln.get('host')
                        enriched_vulns.append(vuln_data)
        
        print("\n")  # New line after progress bar
        
        # Write enriched data
        with open(output_file, 'w') as f:
            json.dump(enriched_vulns, f, indent=2)
            
        print(f"\nProcessing complete:")
        print(f"- Successfully processed: {len(enriched_vulns)} vulnerabilities")
        print(f"- Unique CVEs fetched: {len(cve_cache)}")
        if failed_cves:
            print(f"- Failed to process: {len(failed_cves)} CVEs")
            print("Failed CVEs:")
            for cve in failed_cves:
                print(f"  - {cve}")
        print(f"\nOutput written to {output_file}")
        
    except Exception as e:
        print(f"Error processing vulnerabilities: {str(e)}")

if __name__ == "__main__":
    # Check if folder path is provided
    if len(sys.argv) != 2:
        print("Usage: python enrich_vulnerabilities.py <folder_path>")
        print("Example: python enrich_vulnerabilities.py D:\\Ranger\\Scanner Environment\\ltimindtree_com\\leads")
        sys.exit(1)

    folder_path = sys.argv[1]
    
    # Construct file paths
    input_file = os.path.join(folder_path, 'vulnerabilities.json')
    output_file = os.path.join(folder_path, 'enriched_vulnerabilities.json')
    
    # Organization ID (you can make this configurable)
    organization_id = 1
    
    if not os.path.exists(input_file):
        print(f"Error: Input file {input_file} not found")
        print(f"Please ensure vulnerabilities.json exists in {folder_path}")
        sys.exit(1)
    
    print(f"Processing vulnerabilities from: {input_file}")
    print(f"Output will be saved to: {output_file}")
    
    process_vulnerabilities(input_file, output_file, organization_id) 