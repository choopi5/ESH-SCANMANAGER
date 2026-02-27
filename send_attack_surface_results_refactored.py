#!/usr/bin/env python3
"""
Refactored Attack Surface Results Sender
Uses the new modular api_senders package for clean, maintainable code.
"""
import argparse
import os
import sys
import subprocess
from pathlib import Path

# Import all the refactored sender functions
from api_senders import (
    send_ips_to_api,
    send_ports_to_api,
    send_sensitive_ports_to_api,
    send_subdomains_to_api,
    send_apis_to_api,
    send_alive_to_api,
    send_vulnerabilities_to_api,
    send_bad_tls_assets_to_api,
    send_login_pages_to_api,
    send_credentials_file_to_api,
    create_organization
)

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Send attack surface results to API (Refactored Version)')
    parser.add_argument('project_id', type=int, help='Project ID')
    parser.add_argument('folder_path', help='Path to folder containing scan results')
    parser.add_argument('--fields', nargs='+', choices=[
        'ips', 'ports', 'sensitive_ports', 'subdomains', 'apis', 
        'alive', 'vulnerabilities', 'bad_tls_assets', 'login_pages', 'credentials'
    ], help='Specific fields to send (default: all available fields)')
    parser.add_argument('--org-only', action='store_true', help='Only create new organization, skip attack surface data')
    
    args = parser.parse_args()
    
    project_id = args.project_id
    folder_path = args.folder_path
    selected_fields = args.fields
    
    # Extract project name from folder path (last part)
    project_name = os.path.basename(folder_path.rstrip('/\\'))
    
    print(f"📁 Project: {project_name}")
    print(f"🆔 Project ID: {project_id}")
    print(f"📂 Folder: {folder_path}")
    print(f"🔧 Using REFACTORED modular code (with domain name fix!)")
    
    # Create new organization record
    print(f"\n🏢 Creating new organization record...")
    org_success = create_organization(project_id, project_name)
    if not org_success:
        print(f"⚠️  Warning: Failed to create organization record, but continuing with attack surface...")
    
    # If --org-only flag is set, exit after organization creation
    if args.org_only:
        if org_success:
            print(f"✅ Organization creation completed successfully!")
            sys.exit(0)
        else:
            print(f"❌ Organization creation failed!")
        sys.exit(1)

    # Get the project name from the last part of the folder path
    path_parts = Path(folder_path).parts
    project_name = path_parts[-1] if path_parts else "unknown_project"
    
    print(f"Project name extracted: {project_name}")
    
    # Run nuclei analyzer first (optional)
    print(f"\n{'='*80}")
    print("RUNNING NUCLEI ANALYSIS")
    print(f"{'='*80}")
    
    nuclei_success = False
    try:
        # Check if nuclei analyzer script exists
        nuclei_script = 'nuclei_results_analyzer.py'
        if os.path.exists(nuclei_script):
            print(f"🔍 Running nuclei analyzer on: {folder_path}")
            
            # Run the nuclei analyzer with the full folder path
            script_dir = os.path.dirname(os.path.abspath(nuclei_script))
            script_path = os.path.join(script_dir, nuclei_script)
            
            result = subprocess.run([
                sys.executable, script_path, folder_path
            ], capture_output=True, text=True, cwd=script_dir)
            
            print("Nuclei Analyzer Output:")
            print(result.stdout)
            
            if result.stderr:
                print("Nuclei Analyzer Errors:")
                print(result.stderr)
            
            if result.returncode == 0:
                print("✅ Nuclei analysis completed successfully")
                nuclei_success = True
            else:
                print(f"⚠ Nuclei analysis completed with return code: {result.returncode}")
        else:
            print("⚠ Nuclei analyzer script not found, skipping nuclei analysis")
            
    except Exception as e:
        print(f"❌ Error running nuclei analyzer: {e}")
        print("⚠ Continuing without nuclei analysis...")
    
    print(f"{'='*80}\n")

    # Construct file paths
    ips_file = os.path.join(folder_path, './leads/ips.txt')
    ports_file = os.path.join(folder_path, './leads/ports.txt')
    sensitive_ports_file = os.path.join(folder_path, './findings/sensitive_ports.txt')
    subdomains_file = os.path.join(folder_path, './leads/subdomains.txt')
    apis_file = os.path.join(folder_path, './leads/endpoints.txt')
    alive_file = os.path.join(folder_path, './leads/alive.txt')
    vulnerabilities_file = os.path.join(folder_path, './findings/enriched_vulnerabilities.json')
    bad_tls_assets_file = os.path.join(folder_path, './findings/bad_tls_assets.txt')
    login_pages_file = os.path.join(folder_path, './leads/login_pages.txt')
    credentials_file = os.path.join(folder_path, './findings/credentials.txt')

    # Define field mappings
    field_mappings = {
        'ips': (ips_file, "IP addresses", send_ips_to_api),
        'ports': (ports_file, "Ports", send_ports_to_api),
        'sensitive_ports': (sensitive_ports_file, "Sensitive ports", send_sensitive_ports_to_api),
        'subdomains': (subdomains_file, "Subdomains", send_subdomains_to_api),
        'apis': (apis_file, "APIs", send_apis_to_api),
        'alive': (alive_file, "Alive domains", send_alive_to_api),
        'vulnerabilities': (vulnerabilities_file, "Vulnerabilities", send_vulnerabilities_to_api),
        'bad_tls_assets': (bad_tls_assets_file, "Bad TLS Assets", send_bad_tls_assets_to_api),
        'login_pages': (login_pages_file, "Login Pages", send_login_pages_to_api),
        'credentials': (credentials_file, "Credentials", send_credentials_file_to_api)
    }
    
    # Check if required files exist before proceeding
    print(f"\n{'='*80}")
    print("CHECKING FILES")
    print(f"{'='*80}")
    
    if selected_fields:
        print(f"Selected fields to send: {', '.join(selected_fields)}")
        files_to_check = [(field_mappings[field][0], field_mappings[field][1], field_mappings[field][2]) for field in selected_fields if field in field_mappings]
    else:
        print("No specific fields selected - will send all available files")
        # Define which files are required vs optional when sending all
        required_fields = ['ips', 'ports', 'sensitive_ports', 'subdomains', 'apis', 'alive', 'vulnerabilities', 'login_pages']
        optional_fields = ['credentials', 'bad_tls_assets']
        
        files_to_check = [(field_mappings[field][0], field_mappings[field][1], field_mappings[field][2]) for field in required_fields + optional_fields if field in field_mappings]
    
    missing_files = []
    existing_files = []
    
    # Check files
    for file_path, description, sender_func in files_to_check:
        if os.path.exists(file_path):
            existing_files.append((file_path, description, sender_func))
            print(f"✅ {description}: {file_path}")
        else:
            missing_files.append((file_path, description, sender_func))
            print(f"❌ {description}: {file_path}")
    
    if not existing_files:
        print(f"\n❌ No files found to send. Exiting.")
        sys.exit(1)
    
    # For selected fields, all must be present
    if selected_fields and missing_files:
        print(f"\n❌ Missing required files for selected fields. Cannot proceed:")
        for file_path, description, _ in missing_files:
            print(f"   - {description}: {file_path}")
        print(f"\n❌ All selected field files must be present before sending. Exiting.")
        sys.exit(1)
    # For all fields, only required ones must be present
    elif not selected_fields:
        required_missing = [f for f in missing_files if f[1] in ["IP addresses", "Ports", "Sensitive ports", "Subdomains", "APIs", "Alive domains", "Vulnerabilities"]]
        if required_missing:
            print(f"\n❌ Missing required files. Cannot proceed:")
            for file_path, description, _ in required_missing:
                print(f"   - {description}: {file_path}")
            print(f"\n❌ All required files must be present before sending. Exiting.")
            sys.exit(1)
    
    print(f"\n{'='*80}")
    print("SENDING DATA TO APIs")
    print(f"{'='*80}")
    
    if selected_fields:
        print(f"📤 Sending only selected fields: {', '.join(selected_fields)}")
    else:
        print(f"📤 Sending all available fields")
    
    # Track results for summary
    results = {
        'success': [],
        'failed': [],
        'skipped': []
    }
    
    # Send data from each existing file using the refactored modules
    for file_path, description, sender_func in existing_files:
        print(f"\n📤 Sending {description}...")
        
        try:
            # Call the appropriate refactored sender function
            success = sender_func(project_id, file_path)
            
            if success:
                results['success'].append(description)
            else:
                results['failed'].append(description)
                
        except Exception as e:
            print(f"❌ Exception occurred while sending {description}: {e}")
            results['failed'].append(description)
    
    # Print final summary report
    print(f"\n{'='*80}")
    print("FINAL SUMMARY REPORT")
    print(f"{'='*80}")
    
    total_attempted = len(results['success']) + len(results['failed']) + len(results['skipped'])
    total_success = len(results['success'])
    total_failed = len(results['failed'])
    total_skipped = len(results['skipped'])
    
    print(f"📊 OVERALL RESULTS:")
    print(f"   Total attempted: {total_attempted}")
    print(f"   ✅ Successful: {total_success}")
    print(f"   ❌ Failed: {total_failed}")
    print(f"   ⏭️  Skipped: {total_skipped}")
    
    if total_attempted > 0:
        success_rate = (total_success / total_attempted) * 100
        print(f"   📈 Success rate: {success_rate:.1f}%")
    
    if results['success']:
        print(f"\n✅ SUCCESSFUL OPERATIONS:")
        for item in results['success']:
            print(f"   • {item}")
    
    if results['failed']:
        print(f"\n❌ FAILED OPERATIONS:")
        for item in results['failed']:
            print(f"   • {item}")
    
    if results['skipped']:
        print(f"\n⏭️  SKIPPED OPERATIONS:")
        for item in results['skipped']:
            print(f"   • {item}")
    
    print(f"\n🎯 REFACTORED VERSION BENEFITS:")
    print(f"   ✅ Fixed domain name issue in ports (no more warnings!)")
    print(f"   ✅ Modular, maintainable code structure")
    print(f"   ✅ Better error handling and retry logic")
    print(f"   ✅ Reusable components")
    
    print(f"\n{'='*80}")
    
    if total_failed > 0:
        print(f"⚠️  {total_failed} operation(s) failed. Please check the logs above for details.")
        sys.exit(1)
    else:
        print(f"🎉 All operations completed successfully using the refactored code!") 

if __name__ == "__main__":
    main() 