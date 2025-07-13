#!/usr/bin/env python3
"""
Debug script to see what the ipwhois.io API is actually returning
"""

import requests
import json

def test_ipwhois_api():
    """Test the ipwhois.io API directly"""
    print("="*60)
    print("DEBUGGING IPWHOIS.IO API")
    print("="*60)
    
    test_ip = "8.8.8.8"
    api_key = "5HWMmlG6osK2fXWX"
    
    # Test different URL formats
    urls_to_test = [
        f"https://ipwhois.pro/{test_ip}?key={api_key}",
        f"https://ipwhois.pro/{test_ip}",
        f"http://ipwhois.pro/{test_ip}?key={api_key}",
        f"https://api.ipwhois.io/{test_ip}?key={api_key}",
        f"https://ipwhois.io/{test_ip}?key={api_key}"
    ]
    
    for url in urls_to_test:
        print(f"\n" + "-"*60)
        print(f"Testing URL: {url}")
        print("-"*60)
        
        try:
            response = requests.get(url, timeout=10)
            print(f"Status Code: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Response Text: {response.text}")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"JSON Response: {json.dumps(data, indent=2)}")
                except:
                    print("Response is not valid JSON")
            
        except Exception as e:
            print(f"Error: {e}")

def test_without_key():
    """Test without API key to see free tier response"""
    print(f"\n" + "="*60)
    print("TESTING WITHOUT API KEY (FREE TIER)")
    print("="*60)
    
    test_ip = "8.8.8.8"
    url = f"https://ipwhois.pro/{test_ip}"
    
    try:
        response = requests.get(url, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Response Text: {response.text}")
        
        if response.status_code == 200:
            try:
                data = response.json()
                print(f"JSON Response: {json.dumps(data, indent=2)}")
            except:
                print("Response is not valid JSON")
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_ipwhois_api()
    test_without_key() 