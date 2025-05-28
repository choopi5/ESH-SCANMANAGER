import requests
import json
import urllib3
import socks
import socket

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_api_connection():
    # Test configuration
    server_url = "https://100.20.158.40/api/routes/"
    system_api_key = "3taADSASFDGSFG$#%#^@FDSAsda#H_DSAGR$^$^@@"
    
    # SOCKS5 proxy configuration
    proxy_host = "127.0.0.1"  # Change this to your SOCKS5 proxy host
    proxy_port = 8989         # Change this to your SOCKS5 proxy port

    # Set up the SOCKS5 proxy
    socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
    socket.socket = socks.socksocket

    # Prepare the request
    url = server_url + "ip_addresses.php"  # Note: Added .php extension
    payload = {
        "ip_address": "192.168.1.1",
        "organization_id": 1,
        "hostname": "test.local",
        "country_code": "US",
        "status": "active",
        "notes": "Test IP"
    }
    
    headers = {
        'X-API-Key': system_api_key,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    print("\n=== Testing API Connection ===")
    print(f"URL: {url}")
    print(f"Using SOCKS5 proxy: {proxy_host}:{proxy_port}")
    
    print("\nRequest Headers:")
    for key, value in headers.items():
        print(f"{key}: {value}")
    
    print("\nRequest Payload:")
    print(json.dumps(payload, indent=2))

    try:
        # Send the request
        response = requests.post(
            url, 
            headers=headers, 
            json=payload,
            verify=False,
            timeout=30
        )
        
        print("\n=== Raw Response Details ===")
        print(f"Status Code: {response.status_code}")
        print(f"Status Message: {response.reason}")
        
        print("\nResponse Headers:")
        for key, value in response.headers.items():
            print(f"{key}: {value}")
        
        print("\nRaw Response Content:")
        print("-" * 50)
        print(response.content.decode('utf-8', errors='replace'))
        print("-" * 50)
        
        print("\nResponse Encoding:", response.encoding)
        print("Response Content Type:", response.headers.get('content-type', 'Not specified'))
        
        try:
            print("\nAttempting to parse as JSON:")
            json_response = response.json()
            print("Received JSON Response:")
            print(json.dumps(json_response, indent=2))
        except json.JSONDecodeError as e:
            print(f"Not a valid JSON response: {str(e)}")
            print("Expected JSON format but received non-JSON response")
        
        if response.status_code in [200, 201]:
            print("\n✅ API connection successful!")
            print("The API is working correctly.")
        else:
            print("\n❌ API connection failed!")
            print(f"Status code: {response.status_code}")
            if response.status_code == 500:
                print("Server error (500) - The server encountered an internal error.")
                print("This could be due to:")
                print("1. Invalid request format")
                print("2. Server-side processing error")
                print("3. Database connection issues")
            elif response.status_code == 401:
                print("Unauthorized (401) - Check your API key")
            elif response.status_code == 403:
                print("Forbidden (403) - You don't have permission to access this resource")
            elif response.status_code == 404:
                print("Not Found (404) - The API endpoint might be incorrect")
            print("\nPlease check the response for error details.")

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

if __name__ == "__main__":
    test_api_connection() 