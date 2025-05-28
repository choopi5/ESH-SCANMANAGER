import requests
import time
import subprocess
import urllib3
import socket
import sys

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_api_url():
    api_endpoint = "https://100.20.158.40/api/rest/attack_surface"
    headers = {
        "Authorization": "dKlpFBmj2hwp1voLyc2mwKx4ercKSpWU",
        "Host": "100.20.158.40"
    }
    
    print(f"Attempting to connect to: {api_endpoint}")
    
    # First check if we can resolve the hostname
    try:
        ip_address = socket.gethostbyname("100.20.158.40")
        print(f"Successfully resolved IP address: {ip_address}")
    except socket.gaierror as e:
        print(f"Failed to resolve hostname: {e}")
        return None
    
    # Try to establish a connection to check if the port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('100.20.158.40', 443))
        if result == 0:
            print("Port 443 is open")
        else:
            print(f"Port 443 is closed (error code: {result})")
        sock.close()
    except socket.error as e:
        print(f"Socket error while checking port: {e}")
    
    try:
        print("Sending HTTP request...")
        response = requests.get(api_endpoint, headers=headers, verify=False, timeout=10)
        print(f"Response status code: {response.status_code}")
        
        if response.status_code == 200:
            # Parse the response JSON
            data = response.json()
            print(f"API Response: {data}")
            
            # Handle both list and dictionary response formats
            if isinstance(data, list):
                # If it's a list, get the target from the first item
                if data and len(data) > 0:
                    if isinstance(data[0], dict):
                        return data[0].get('target')
                    else:
                        print("First item in list is not a dictionary")
                        return None
                else:
                    print("Empty list returned from API")
                    return None
            elif isinstance(data, dict):
                # If it's a dictionary, try both 'url' and 'target' keys
                if 'target' in data:
                    return data.get('target')
                else:
                    return data.get('url')
            else:
                print(f"Unexpected response type: {type(data)}")
                return None
        else:
            print(f"API request failed with status code: {response.status_code}")
            print(f"Response content: {response.text}")
            return None
    except requests.exceptions.SSLError as e:
        print(f"SSL Error: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: {e}")
        return None
    except requests.exceptions.Timeout as e:
        print(f"Request timed out: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        print(f"Error type: {type(e)}")
        return None

def main():
    #while True:
        url = fetch_api_url()
        if url:
            try:
                # Replace 'local_script.py' with your actual script name
                subprocess.run(['python', 'local_script.py', url], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error running local script: {e}")
        else:
            print("Failed to get URL from API")
        
        # Wait for 10 minutes before next request
        #time.sleep(600)

if __name__ == "__main__":
    main()
