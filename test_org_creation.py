#!/usr/bin/env python3
"""
Test script for organization creation
"""
import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from api_senders import create_organization

def test_create_organization():
    """Test organization creation with detailed debugging"""
    project_id = 99999  # Test project ID
    domain_name = "test-domain.com"
    
    print("="*60)
    print("TESTING ORGANIZATION CREATION")
    print("="*60)
    print(f"Project ID: {project_id}")
    print(f"Domain Name: {domain_name}")
    print("="*60)
    
    try:
        result = create_organization(project_id, domain_name)
        print(f"\nResult: {result}")
        return result
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_create_organization() 