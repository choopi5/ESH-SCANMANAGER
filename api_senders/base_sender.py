"""
Base module for API senders with common imports and utilities.
"""
import requests
import json
import urllib3
import os
import sys
import time
from datetime import datetime
from pathlib import Path
import re

# Import from parent directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import API_BASE_URL, API_KEY, PROXY_HOST, PROXY_PORT
from ip_location import get_location_info, get_bulk_location_info, is_valid_ip
from modules.utils import parse_ips_from_file
from enrich_vulnerabilities import normalize_severity

# Disable InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SOCKS proxy disabled - not required anymore
# import socks
# import socket
# socks.set_default_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
# socket.socket = socks.socksocket

def get_default_location():
    """Return default location data for non-IP entries"""
    return {
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

def get_api_headers():
    """Return standard API headers"""
    return {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

def send_request_with_retry(url, payload, headers, max_retries=3):
    """Send request with retry logic"""
    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=payload, verify=False)
            return response
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                raise e
            print(f"Request failed, retrying ({attempt + 1}/{max_retries})...")
            time.sleep(1)
    return None 