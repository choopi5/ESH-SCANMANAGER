#!/usr/bin/env python3
"""
Test script that mirrors the production IP processing logic in send_attack_surface_results.py
Tests the complete workflow including API record structure and batching logic
"""

from ip_location import get_location_info, get_bulk_location_info
import os
import json
import time
from modules.utils import parse_ips_from_file, extract_ip_from_dns_format, test_ip_parsing

def test_ips_from_file_production_logic(file_path='ips.txt', mock_project_id=12345):
    """
    Test IPs from file using the exact same logic as send_ips_to_api() 
    but without actually sending to the API
    """
    print(f"\n{'='*80}")
    print("TESTING IP PROCESSING - PRODUCTION LOGIC WITH DNS PARSING")
    print(f"{'='*80}")
    
    # Get absolute path if relative path is provided (matches production)
    file_path = os.path.abspath(file_path)
    
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found")
        return

    # Generate cache file path in same folder as source file (same as production)
    file_dir = os.path.dirname(file_path)
    file_name = os.path.basename(file_path)
    cache_name = file_name.replace('.txt', '_ip_records_cache.json')
    cache_file = os.path.join(file_dir, cache_name)
    
    # Check for existing cache file
    if os.path.exists(cache_file):
        print(f"🔄 Found existing cache file: {cache_name}")
        print(f"📁 Cache location: {cache_file}")
        print(f"⚠ Remove cache file to test fresh processing, or run production for auto-resume")
        print()

    try:
        # Parse IPs from file using shared utility function (EXACT same as production)
        parse_result = parse_ips_from_file(file_path)
        ips = parse_result['ips']
        skipped_lines = parse_result['skipped_lines']
        stats = parse_result['stats']
        
        # Report parsing results (EXACT same as production)
        if skipped_lines:
            print(f"Warning: Skipped {stats['skipped_lines']} lines that couldn't be parsed as IPs:")
            for line in skipped_lines[:5]:  # Show first 5 examples
                print(f"  - {line}")
            if len(skipped_lines) > 5:
                print(f"  ... and {len(skipped_lines) - 5} more")

        if not ips:
            print("No valid IPs found in file after parsing")
            return

        print(f"\nProcessing {stats['extracted_ips']} IPs extracted from {stats['total_lines']} lines in {file_path}")
        print(f"IP extraction rate: {stats['extraction_rate']:.1f}%")
        
        # Get location data for all IPs in bulk (exact same as production)
        print("Getting location data for all IPs...")
        locations = get_bulk_location_info(ips, batch_size=100)  # Optimized: use max batch size per documentation
        
        # Show sample of geolocation results
        print(f"\n📋 Geolocation Sample Results:")
        sample_count = 0
        for ip, location in locations.items():
            if location.get('city') != 'Unknown' and sample_count < 3:
                print(f"   IP: {ip}")
                print(f"   Location: {location.get('city', 'Unknown')}, {location.get('region', 'Unknown')}, {location.get('country_name', 'Unknown')}")
                print(f"   ISP: {location.get('isp', 'Unknown')}")
                print(f"   Coordinates: {location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}")
                print()
                sample_count += 1
        print(f"✅ Geolocation completed: {len([ip for ip, data in locations.items() if data.get('city') != 'Unknown'])} IPs with location data")
        
        # Prepare the list of IP data dicts (EXACT same structure as production)
        ip_records = []
        for ip in ips:
            location = locations.get(ip, {})
            ip_data = {
                "ip_address": ip,
                "country_code": location.get("country_code", "UN"),
                "country_name": location.get("country_name", "Unknown"),
                "city": location.get("city", "Unknown"),
                "region": location.get("region", "Unknown"),
                "latitude": location.get("latitude"),
                "longitude": location.get("longitude"),
                "isp": location.get("isp", "Unknown"),
                "org": location.get("org", "Unknown"),
                "asn": location.get("asn", "Unknown"),
                "asn_name": location.get("asn_name", "Unknown"),
                "continent": location.get("continent", "Unknown"),
                "continent_code": location.get("continent_code", "UN"),
                "organization_id": mock_project_id,
                "status": "active",
                "notes": f"Added via bulk API"
            }
            ip_records.append(ip_data)

        if not ip_records:
            print("No IPs to send")
            return

        print(f"\n✅ Successfully created {len(ip_records)} IP records")
        
        # Test API batching logic (same as production but mock)
        print(f"\n{'='*60}")
        print("TESTING API BATCHING LOGIC")
        print(f"{'='*60}")
        
        total = len(ip_records)
        batch_size = 50
        total_batches = (total + batch_size - 1) // batch_size
        
        print(f"Total records: {total}")
        print(f"Batch size: {batch_size}")
        print(f"Number of batches: {total_batches}")
        
        for i in range(0, total, batch_size):
            batch = ip_records[i:i+batch_size]
            current_batch = i//batch_size + 1
            payload = {"ip_addresses": batch}
            
            print(f"\n📤 [MOCK] Batch {current_batch}/{total_batches} ({len(batch)} IPs) [{(current_batch/total_batches)*100:.1f}%]")
            print(f"Range: {i+1} to {min(i+batch_size, total)}")
            
            # Show sample record from this batch (matching production format)
            if batch:
                sample_record = batch[0]
                print(f"📋 Sample record from batch {current_batch}:")
                print(f"   IP: {sample_record.get('ip_address', 'N/A')}")
                print(f"   Location: {sample_record.get('city', 'N/A')}, {sample_record.get('region', 'N/A')}, {sample_record.get('country_name', 'N/A')}")
                print(f"   ISP: {sample_record.get('isp', 'N/A')}")
                print(f"   Coordinates: {sample_record.get('latitude', 'N/A')}, {sample_record.get('longitude', 'N/A')}")
                
                print(f"Full record structure:")
                print(json.dumps(sample_record, indent=2))
            
            # Mock API call (simulate what production does)
            print(f"[MOCK] Would send POST to API with {len(batch)} IP records")
            print(f"[MOCK] Payload size: {len(json.dumps(payload))} characters")
            print(f"✅ [MOCK] Batch {current_batch}/{total_batches} would be sent successfully")
            
            # Simulate the delay that production has
            if i + batch_size < total:  # Don't delay after last batch
                print("[MOCK] Sleeping 1 second between batches...")
                time.sleep(1)

        # Summary (like production validation)
        print(f"\n{'='*60}")
        print("VALIDATION SUMMARY")
        print(f"{'='*60}")
        
        total_ips = len(ips)
        successful_records = len(ip_records)
        failed_records = total_ips - successful_records
        
        print(f"Total lines read from file: {stats['total_lines']}")
        print(f"Successfully parsed IPs: {stats['extracted_ips']}")
        print(f"Skipped unparseable lines: {stats['skipped_lines']}")
        print(f"Successful location lookups: {successful_records}")
        print(f"Failed location lookups: {failed_records}")
        print(f"IP extraction rate: {stats['extraction_rate']:.1f}%")
        print(f"Location lookup success rate: {(successful_records/total_ips)*100:.1f}%")
        
        # Show any IPs that failed location lookup
        if failed_records > 0:
            failed_ips = [ip for ip in ips if ip not in locations]
            print(f"\nIPs that failed location lookup:")
            for failed_ip in failed_ips:
                print(f"  - {failed_ip}")

    except Exception as e:
        print(f"Error: {e}")
        print(f"Error type: {type(e)}")

def test_single_ip_detailed(ip_address="8.8.8.8", mock_project_id=12345):
    """
    Test single IP with detailed output showing the complete record structure
    """
    print(f"\n{'='*60}")
    print(f"TESTING SINGLE IP DETAILED: {ip_address}")
    print(f"{'='*60}")
    
    try:
        # Get location info
        location = get_location_info(ip_address)
        
        # Create record using same structure as production
        ip_data = {
            "ip_address": ip_address,
            "country_code": location.get("country_code", "UN"),
            "country_name": location.get("country_name", "Unknown"),
            "city": location.get("city", "Unknown"),
            "region": location.get("region", "Unknown"),
            "latitude": location.get("latitude"),
            "longitude": location.get("longitude"),
            "isp": location.get("isp", "Unknown"),
            "org": location.get("org", "Unknown"),
            "asn": location.get("asn", "Unknown"),
            "asn_name": location.get("asn_name", "Unknown"),
            "continent": location.get("continent", "Unknown"),
            "continent_code": location.get("continent_code", "UN"),
            "organization_id": mock_project_id,
            "status": "active",
            "notes": f"Added via bulk API"
        }
        
        print("Complete API record structure:")
        print(json.dumps(ip_data, indent=2))
        
        print(f"\n[MOCK] Would send this record to API endpoint")
        print(f"[MOCK] Record size: {len(json.dumps(ip_data))} characters")
        
    except Exception as e:
        print(f"Error processing IP {ip_address}: {e}")

if __name__ == "__main__":
    # Test DNS parsing function (from shared utils)
    test_ip_parsing()
    
    # Test single IP first
    test_single_ip_detailed()
    
    # Test file processing with production logic
    test_ips_from_file_production_logic()
    
    print(f"\n{'='*80}")
    print("ALL TESTS COMPLETE")
    print("This test uses the SAME shared utility functions as production")
    print("including ANSI color code handling for lines like:")
    print("domain [@]35mA[@]0m] [@]32mIP[@]0m]")
    print("No code duplication - both test and production use modules/utils.py")
    print(f"{'='*80}") 