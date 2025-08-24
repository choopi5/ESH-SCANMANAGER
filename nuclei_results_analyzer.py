#!/usr/bin/env python3
"""
Generic Nuclei Results Analyzer
===============================

This script analyzes Nuclei scan results and categorizes them into:
1. SSL/TLS specific findings (for Bad TLS Assets API)
2. Other relevant findings (for general vulnerability tracking)

Usage:
    python nuclei_results_analyzer.py [options]

Options:
    --all-results FILE     Path to nuclei_all_results.txt (default: ./findings/nuclei_all_results.txt)
    --info-results FILE    Path to nuclei_info_results.txt (default: ./findings/nuclei_info_results.txt)
    --output-dir DIR       Output directory (default: ./findings/analyzed)
    --project-name NAME    Project name for reporting (default: "Project")
    --help                 Show this help message
"""

import os
import sys
import re
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

class NucleiResultsAnalyzer:
    """Generic analyzer for Nuclei scan results"""
    
    def __init__(self, project_name="Project"):
        self.project_name = project_name
        
        # SSL/TLS security vulnerabilities that should go to Bad TLS Assets API
        # Only actual security issues, not informational findings
        self.ssl_finding_types = {
            'weak-cipher-suites:tls-1.0',
            'weak-cipher-suites:tls-1.1',
            'deprecated-tls:tls_1.1',
            'deprecated-tls:tls_1.0', 
            'expired-ssl',
            'self-signed-ssl',
            'mismatched-ssl-certificate',
            'kubernetes-fake-certificate',
            'weak-cipher'
        }
        
        # SSL/TLS informational findings that should be ignored (not written to any file)
        self.ssl_info_findings = {
            'ssl-issuer',
            'ssl-dns-names', 
            'wildcard-tls',
            'tls-version',
            'ssl-cert'
        }
        
        # High-priority finding types for general vulnerability tracking
        self.high_priority_findings = {
            'prometheus-metrics',
            'debug-vars',
            'wordpress-admin-menu-editor:outdated_version',
            'wordpress-enable-media-replace:outdated_version',
            'wordpress-regenerate-thumbnails:detected_version',
            'wordpress-redirection:outdated_version',
            'wordpress-wordfence:outdated_version',
            'wordpress-wordpress-seo:outdated_version',
            'wordpress-wp-pagenavi:detected_version',
            'wp-yoast-user-enumeration',
            'http-missing-security-headers',
            'cookies-without-httponly',
            'cookies-without-secure',
            'missing-sri',
            'graphql-detect',
            'graphql-field-suggestion',
            'graphql-wpgraphql-detect',
            'waf-detect',
            'aws-detect',
            'tech-detect',
            'form-detection',
            'options-method',
            'sitemap-detect',
            'robots-txt',
            'robots-txt-endpoint',
            'composer-config',
            'wp-license-file',
            'readme-md',
            'wordpress-login',
            'package-json',
            'wordpress-rdf-user-enum',
            'bigip-detect',
            'security-txt',
            's3-detect',
            'mx-fingerprint',
            'caa-fingerprint',
            'txt-fingerprint',
            'spf-record-detect',
            'dns-saas-service-detection',
            'nameserver-fingerprint',
            'dmarc-detect',
            'email-extractor',
            'addeventlistener-detect',
            'xss-deprecated-header',
            'google-floc-disabled',
            'discord-invite-detect',
            'metatag-cms',
            'wordpress-plugin-detect',
            'wordpress-detect'
        }
        
        # Statistics tracking
        self.stats = {
            'total_findings': 0,
            'ssl_findings': 0,
            'high_priority_findings': 0,
            'other_findings': 0,
            'unique_hosts': set(),
            'unique_ssl_hosts': set(),
            'finding_types': {},
            'severity_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0, 'info': 0}
        }

    def parse_nuclei_line(self, line: str) -> Dict:
        """Parse a single Nuclei result line"""
        line = line.strip()
        if not line:
            return None
            
        # Standard Nuclei format: [finding-type] [protocol] [severity] hostname:port ["details"]
        pattern = r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+([^:]+):(\d+)\s*(?:\["([^"]*)"\])?'
        match = re.match(pattern, line)
        
        if match:
            finding_type, protocol, severity, hostname, port, details = match.groups()
            return {
                'finding_type': finding_type,
                'protocol': protocol,
                'severity': severity,
                'hostname': hostname,
                'port': int(port),
                'details': details if details else '',
                'raw_line': line
            }
        
        return None

    def is_ssl_finding(self, finding: Dict) -> bool:
        """Check if a finding is SSL/TLS related security vulnerability"""
        if not finding:
            return False
            
        # Only check explicit SSL security finding types
        # No keyword matching to avoid including informational findings
        if finding['finding_type'] in self.ssl_finding_types:
            return True
            
        # Check if protocol is SSL and it's an actual security issue
        if finding['protocol'] == 'ssl' and finding['finding_type'] in self.ssl_finding_types:
            return True
            
        return False
    
    def is_ssl_info_finding(self, finding: Dict) -> bool:
        """Check if a finding is SSL/TLS informational (should be ignored)"""
        if not finding:
            return False
            
        # Check if finding type is in SSL info findings list
        if finding['finding_type'] in self.ssl_info_findings:
            return True
            
        return False

    def is_high_priority(self, finding: Dict) -> bool:
        """Check if a finding is high priority"""
        if not finding:
            return False
            
        # Check if finding type is in high priority list
        if finding['finding_type'] in self.high_priority_findings:
            return True
            
        # Check severity
        if finding['severity'] in ['high', 'critical']:
            return True
            
        return False

    def analyze_file(self, file_path: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """Analyze a Nuclei results file and categorize findings"""
        ssl_findings = []
        high_priority_findings = []
        other_findings = []
        
        if not os.path.exists(file_path):
            print(f"Warning: File not found: {file_path}")
            return [], [], []
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    finding = self.parse_nuclei_line(line)
                    if not finding:
                        continue
                        
                    self.stats['total_findings'] += 1
                    self.stats['unique_hosts'].add(finding['hostname'])
                    
                    # Track finding types
                    finding_type = finding['finding_type']
                    self.stats['finding_types'][finding_type] = self.stats['finding_types'].get(finding_type, 0) + 1
                    
                    # Track severity distribution
                    severity = finding['severity']
                    if severity in self.stats['severity_distribution']:
                        self.stats['severity_distribution'][severity] += 1
                    
                    # Categorize finding
                    if self.is_ssl_finding(finding):
                        ssl_findings.append(finding)
                        self.stats['ssl_findings'] += 1
                        self.stats['unique_ssl_hosts'].add(finding['hostname'])
                    elif self.is_ssl_info_finding(finding):
                        # Skip informational SSL findings - don't write to any file
                        continue
                    elif self.is_high_priority(finding):
                        high_priority_findings.append(finding)
                        self.stats['high_priority_findings'] += 1
                        # Debug: Print high priority findings
                        if finding['finding_type'] == 'prometheus-metrics':
                            print(f"DEBUG: Found prometheus-metrics: {finding['raw_line']}")
                    else:
                        other_findings.append(finding)
                        self.stats['other_findings'] += 1
                        
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return [], [], []
            
        return ssl_findings, high_priority_findings, other_findings

    def format_ssl_findings_for_api(self, ssl_findings: List[Dict]) -> str:
        """Format SSL findings for the Bad TLS Assets API"""
        formatted_lines = []
        
        for finding in ssl_findings:
            # Format: https://hostname:port [finding-type] details
            url = f"https://{finding['hostname']}:{finding['port']}"
            finding_type = finding['finding_type']
            details = finding['details'] if finding['details'] else f"{finding['protocol']} {finding['severity']} finding"
            
            formatted_line = f"{url} [{finding_type}] {details}"
            formatted_lines.append(formatted_line)
            
        return '\n'.join(formatted_lines)

    def create_summary_report(self, output_dir: str):
        """Create a comprehensive summary report"""
        report = {
            'project_name': self.project_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'statistics': {
                'total_findings': self.stats['total_findings'],
                'ssl_findings': self.stats['ssl_findings'],
                'high_priority_findings': self.stats['high_priority_findings'],
                'other_findings': self.stats['other_findings'],
                'unique_hosts': len(self.stats['unique_hosts']),
                'unique_ssl_hosts': len(self.stats['unique_ssl_hosts']),
                'severity_distribution': self.stats['severity_distribution']
            },
            'finding_types': self.stats['finding_types'],
            'ssl_finding_types': list(self.ssl_finding_types),
            'high_priority_finding_types': list(self.high_priority_findings)
        }
        
        report_file = os.path.join(output_dir, 'analysis_summary.json')
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        return report_file

    def print_analysis_summary(self):
        """Print a formatted analysis summary"""
        print(f"\n" + "="*80)
        print(f"NUCLEI RESULTS ANALYSIS SUMMARY - {self.project_name}")
        print("="*80)
        
        print(f"\nFINDINGS STATISTICS:")
        print(f"   Total Findings: {self.stats['total_findings']}")
        print(f"   SSL/TLS Findings: {self.stats['ssl_findings']}")
        print(f"   High Priority Findings: {self.stats['high_priority_findings']}")
        print(f"   Other Findings: {self.stats['other_findings']}")
        
        print(f"\nHOST STATISTICS:")
        print(f"   Unique Hosts: {len(self.stats['unique_hosts'])}")
        print(f"   Hosts with SSL Issues: {len(self.stats['unique_ssl_hosts'])}")
        
        print(f"\nSEVERITY DISTRIBUTION:")
        for severity, count in self.stats['severity_distribution'].items():
            if count > 0:
                print(f"   {severity.upper()}: {count}")
        
        print(f"\nTOP FINDING TYPES:")
        sorted_types = sorted(self.stats['finding_types'].items(), key=lambda x: x[1], reverse=True)
        for finding_type, count in sorted_types[:10]:
            print(f"   {finding_type}: {count}")
        
        print(f"\nSSL FINDING TYPES DETECTED:")
        ssl_types_found = [ft for ft in self.stats['finding_types'].keys() if self.is_ssl_finding({'finding_type': ft, 'protocol': 'ssl', 'severity': 'low'})]
        for ssl_type in ssl_types_found:
            count = self.stats['finding_types'][ssl_type]
            print(f"   {ssl_type}: {count}")
        
        print("="*80)

def main():
    parser = argparse.ArgumentParser(
        description='Analyze Nuclei scan results and create TLS and remaining findings files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python nuclei_results_analyzer.py redis_io
  python nuclei_results_analyzer.py company_scan
  python nuclei_results_analyzer.py test_project
        """
    )
    
    parser.add_argument('folder_name', 
                       help='Name of the folder containing the scan results (e.g., redis_io)')
    
    parser.add_argument('--project-name', 
                       default=None,
                       help='Project name for reporting (default: auto-detected from folder)')
    
    args = parser.parse_args()
    
    # Construct paths based on folder name
    base_path = f"D:\\Ranger\\Data\\{args.folder_name}"
    all_results_file = os.path.join(base_path, 'findings', 'nuclei_all_results.txt')
    info_results_file = os.path.join(base_path, 'findings', 'nuclei_info_results.txt')
    output_dir = os.path.join(base_path, 'findings')  # Write to same folder as input
    
    # Auto-detect project name if not provided
    project_name = args.project_name or args.folder_name.replace('_', ' ').title()
    
    print("Starting Nuclei Results Analysis...")
    print(f"Project: {project_name}")
    print(f"Input files: {all_results_file}, {info_results_file}")
    print(f"Output directory: {output_dir}")
    
    # Check if input files exist
    if not os.path.exists(all_results_file):
        print(f"Error: File not found: {all_results_file}")
        sys.exit(1)
    
    if not os.path.exists(info_results_file):
        print(f"Error: File not found: {info_results_file}")
        sys.exit(1)
    
    analyzer = NucleiResultsAnalyzer(project_name)
    
    # Analyze all results file
    print(f"\nAnalyzing {all_results_file}...")
    ssl_findings_all, high_priority_all, other_all = analyzer.analyze_file(all_results_file)
    
    # Analyze info results file
    print(f"Analyzing {info_results_file}...")
    ssl_findings_info, high_priority_info, other_info = analyzer.analyze_file(info_results_file)
    
    # Combine results
    all_ssl_findings = ssl_findings_all + ssl_findings_info
    all_high_priority = high_priority_all + high_priority_info
    all_other = other_all + other_info
    
    # Remove duplicates based on raw_line
    seen_lines = set()
    unique_ssl_findings = []
    for finding in all_ssl_findings:
        if finding['raw_line'] not in seen_lines:
            unique_ssl_findings.append(finding)
            seen_lines.add(finding['raw_line'])
    
    # Create output files
    print(f"\nCreating output files...")
    
    # TLS findings file (for Bad TLS Assets API)
    tls_output_file = os.path.join(output_dir, 'bad_tls_assets.txt')
    ssl_formatted = analyzer.format_ssl_findings_for_api(unique_ssl_findings)
    with open(tls_output_file, 'w') as f:
        f.write(ssl_formatted)
    print(f"   TLS findings saved to: {tls_output_file}")
    
    # Remaining findings file (all non-TLS findings)
    remaining_output_file = os.path.join(output_dir, 'remaining_findings.txt')
    with open(remaining_output_file, 'w') as f:
        for finding in all_high_priority:
            f.write(finding['raw_line'] + '\n')
        for finding in all_other:
            f.write(finding['raw_line'] + '\n')
    print(f"   Remaining findings saved to: {remaining_output_file}")
    
    # Print summary
    analyzer.print_analysis_summary()
    
    print(f"\nAnalysis complete! Files saved to: {output_dir}")
    print(f"\nReady to send to APIs:")
    print(f"   - {tls_output_file} -> Bad TLS Assets API")
    print(f"   - {remaining_output_file} -> General vulnerability tracking")

if __name__ == "__main__":
    main() 