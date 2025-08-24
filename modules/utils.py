#!/usr/bin/env python3
"""
Shared utility functions for IP processing and parsing
"""

import re
import ipaddress

def extract_ip_from_dns_format(line):
    """
    Extract IP address from DNS resolution output by finding the IP at the end of the line.
    
    Much simpler approach: IP is always the last valid IP address in the line.
    Works with any format including ANSI colors, brackets, etc.
    
    Args:
        line (str): Line of text that may contain an IP address
        
    Returns:
        str or None: Extracted IP address or None if no valid IP found
    """
    line = line.strip()
    
    # Check if it's already a plain IP
    if is_valid_ip(line):
        return line
    
    # Strategy: Find all potential IPs in the line, return the last valid one
    # This handles any format since IP is always at the end
    
    # Find all IPv4 addresses (xxx.xxx.xxx.xxx) - no word boundaries due to ANSI codes
    ipv4_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    ipv4_matches = re.findall(ipv4_pattern, line)
    
    # Check IPv4 matches from end to beginning (IP is usually last)
    for potential_ip in reversed(ipv4_matches):
        if is_valid_ip(potential_ip):
            return potential_ip
    
    # Find all IPv6 addresses - no word boundaries due to ANSI codes
    ipv6_pattern = r'([0-9a-fA-F:]+::[0-9a-fA-F:]*|[0-9a-fA-F:]+:[0-9a-fA-F:]+:[0-9a-fA-F:]+)'
    ipv6_matches = re.findall(ipv6_pattern, line)
    
    # Check IPv6 matches from end to beginning
    for potential_ip in reversed(ipv6_matches):
        if is_valid_ip(potential_ip):
            return potential_ip
    
    return None

def is_valid_ip(ip_str):
    """
    Check if the string is a valid IPv4 or IPv6 address
    
    Args:
        ip_str (str): String to validate as IP address
        
    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str):
    """
    Check if an IP address is private/local
    
    Args:
        ip_str (str): IP address string
        
    Returns:
        bool: True if private/local IP, False if public
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def parse_ips_from_file(file_path):
    """
    Parse IP addresses from a file containing various DNS resolution formats
    
    Args:
        file_path (str): Path to file containing IP data
        
    Returns:
        dict: {
            'ips': list of extracted valid IPs,
            'skipped_lines': list of lines that couldn't be parsed,
            'total_lines': total lines processed,
            'stats': parsing statistics
        }
    """
    try:
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file.readlines()]
            lines = [line for line in lines if line]  # Remove empty lines
    except Exception as e:
        raise Exception(f"Error reading file {file_path}: {e}")

    # Extract IPs from various formats
    ips = []
    skipped_lines = []
    
    for line in lines:
        extracted_ip = extract_ip_from_dns_format(line)
        if extracted_ip:
            ips.append(extracted_ip)
        else:
            skipped_lines.append(line)
    
    # Calculate statistics
    total_lines = len(lines)
    extracted_count = len(ips)
    skipped_count = len(skipped_lines)
    extraction_rate = (extracted_count / total_lines * 100) if total_lines > 0 else 0
    
    stats = {
        'total_lines': total_lines,
        'extracted_ips': extracted_count,
        'skipped_lines': skipped_count,
        'extraction_rate': extraction_rate
    }
    
    return {
        'ips': ips,
        'skipped_lines': skipped_lines,
        'total_lines': total_lines,
        'stats': stats
    }

def test_ip_parsing():
    """
    Test the IP parsing function with various formats including ANSI colors
    """
    print("Testing IP parsing with various formats:")
    print("=" * 60)
    
    test_cases = [
        # ANSI colored DNS format (from your actual file)
        "_wildcard.aperture.paloaltonetworks.com [\x1b[35mA\x1b[0m] [\x1b[32m52.8.61.72\x1b[0m]",
        "8.verdicts.iot.paloaltonetworks.com [\x1b[35mA\x1b[0m] [\x1b[32m52.11.166.136\x1b[0m]",
        "a1.crtx.us.paloaltonetworks.com [\x1b[35mAAAA\x1b[0m] [\x1b[32m2600:1901:0:ce4a::5\x1b[0m]",
        
        # Standard DNS format
        "xsiam.iot.paloaltonetworks.com [A] [52.10.255.77]",
        "example.com [AAAA] [2001:db8::1]",
        
        # Plain IPs
        "192.168.1.1",
        "8.8.8.8",
        "2001:db8::1",
        
        # Mixed formats
        "domain.com has IP 192.168.1.100",
        "server at 10.0.0.1 is running",
        
        # Invalid formats
        "just-a-domain.com",
        "invalid text",
        ""
    ]
    
    for test_case in test_cases:
        result = extract_ip_from_dns_format(test_case)
        status = "✅ EXTRACTED" if result else "❌ SKIPPED"
        print(f"{status}: '{test_case[:50]}...' -> {result}")

if __name__ == "__main__":
    test_ip_parsing()
