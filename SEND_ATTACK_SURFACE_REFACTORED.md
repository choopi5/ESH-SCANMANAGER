# Send Attack Surface Results Refactored - Command Line Usage

## Overview

`send_attack_surface_results_refactored.py` is a refactored Python script that sends attack surface scan results to an API. It uses a modular `api_senders` package for clean, maintainable code and includes improved error handling and retry logic.

## Prerequisites

- Python 3.x installed
- Required dependencies installed (`pip install -r requirements.txt`)
- Valid `config.py` file with API configuration
- Scan results folder with the expected file structure

## Basic Usage

```bash
python send_attack_surface_results_refactored.py <project_id> <folder_path>
```

## Command-Line Arguments

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| `project_id` | Integer | The ID of the project to associate the results with |
| `folder_path` | String | Path to the folder containing scan results |

### Optional Arguments

| Argument | Description |
|----------|-------------|
| `--fields` | Specific fields to send (space-separated). If not specified, all available fields will be sent. |
| `--org-only` | Only create new organization record, skip sending attack surface data |

### Available Field Options

When using `--fields`, you can specify one or more of the following:

- `ips` - IP addresses
- `ports` - Ports
- `sensitive_ports` - Sensitive ports
- `subdomains` - Subdomains
- `apis` - API endpoints
- `alive` - Alive domains
- `vulnerabilities` - Vulnerabilities
- `bad_tls_assets` - Bad TLS Assets
- `login_pages` - Login Pages
- `credentials` - Credentials

## Usage Examples

### Example 1: Send All Available Data

```bash
python send_attack_surface_results_refactored.py 123 "C:\path\to\scan\results"
```

### Example 2: Send Only Specific Fields

```bash
python send_attack_surface_results_refactored.py 123 "C:\path\to\scan\results" --fields ips ports subdomains
```

### Example 3: Send Multiple Specific Fields

```bash
python send_attack_surface_results_refactored.py 123 "C:\path\to\scan\results" --fields ips ports subdomains apis alive vulnerabilities
```

### Example 4: Only Create Organization (Skip Data Sending)

```bash
python send_attack_surface_results_refactored.py 123 "C:\path\to\scan\results" --org-only
```

### Example 5: Using Relative Paths

```bash
python send_attack_surface_results_refactored.py 123 "./scan_results/project_name"
```

## Expected File Structure

The script expects the following file structure within the specified `folder_path`:

```
folder_path/
├── leads/
│   ├── ips.txt
│   ├── ports.txt
│   ├── subdomains.txt
│   ├── endpoints.txt
│   ├── alive.txt
│   └── login_pages.txt
└── findings/
    ├── sensitive_ports.txt
    ├── enriched_vulnerabilities.json
    ├── bad_tls_assets.txt
    └── credentials.txt
```

### File Descriptions

| File | Description | Required |
|------|-------------|----------|
| `leads/ips.txt` | List of IP addresses | Yes* |
| `leads/ports.txt` | List of ports in IP:PORT format | Yes* |
| `leads/subdomains.txt` | List of subdomains | Yes* |
| `leads/endpoints.txt` | List of API endpoints | Yes* |
| `leads/alive.txt` | List of alive hosts/domains | Yes* |
| `leads/login_pages.txt` | List of login pages | Yes* |
| `findings/sensitive_ports.txt` | List of sensitive ports | Yes* |
| `findings/enriched_vulnerabilities.json` | JSON file with vulnerability data | Yes* |
| `findings/bad_tls_assets.txt` | List of assets with bad TLS configuration | No |
| `findings/credentials.txt` | List of credentials | No |

*Required when sending all fields (default behavior). When using `--fields`, only the specified field files are required.

## Script Behavior

### 1. Organization Creation
- The script first creates a new organization record using the project ID and project name (extracted from the folder path)
- If `--org-only` flag is used, the script exits after organization creation

### 2. Nuclei Analysis (Optional)
- The script automatically runs `nuclei_results_analyzer.py` if it exists in the same directory
- This step is optional and the script will continue even if nuclei analysis fails or is skipped

### 3. File Validation
- The script checks for the existence of required files
- Reports which files are found (✅) and which are missing (❌)
- If using `--fields`, all specified field files must be present
- If sending all fields, only required files must be present (optional files like `credentials` and `bad_tls_assets` are allowed to be missing)

### 4. Data Sending
- Sends data from each available file to the API using the appropriate sender function
- Tracks success/failure for each operation
- Provides detailed progress output

### 5. Summary Report
- Displays a final summary with:
  - Total operations attempted
  - Number of successful operations
  - Number of failed operations
  - Success rate percentage
  - Detailed lists of successful and failed operations

## Output Example

```
📁 Project: example_project
🆔 Project ID: 123
📂 Folder: C:\path\to\scan\results
🔧 Using REFACTORED modular code (with domain name fix!)

🏢 Creating new organization record...
✅ Organization created successfully

================================================================================
RUNNING NUCLEI ANALYSIS
================================================================================
🔍 Running nuclei analyzer on: C:\path\to\scan\results
✅ Nuclei analysis completed successfully

================================================================================
CHECKING FILES
================================================================================
✅ IP addresses: C:\path\to\scan\results\leads\ips.txt
✅ Ports: C:\path\to\scan\results\leads\ports.txt
✅ Subdomains: C:\path\to\scan\results\leads\subdomains.txt
...

================================================================================
SENDING DATA TO APIs
================================================================================
📤 Sending all available fields

📤 Sending IP addresses...
✅ Successfully sent IP addresses

📤 Sending Ports...
✅ Successfully sent Ports

...

================================================================================
FINAL SUMMARY REPORT
================================================================================
📊 OVERALL RESULTS:
   Total attempted: 9
   ✅ Successful: 9
   ❌ Failed: 0
   ⏭️  Skipped: 0
   📈 Success rate: 100.0%

✅ SUCCESSFUL OPERATIONS:
   • IP addresses
   • Ports
   • Subdomains
   ...

🎯 REFACTORED VERSION BENEFITS:
   ✅ Fixed domain name issue in ports (no more warnings!)
   ✅ Modular, maintainable code structure
   ✅ Better error handling and retry logic
   ✅ Reusable components

================================================================================
🎉 All operations completed successfully using the refactored code!
```

## Error Handling

- If no files are found, the script exits with error code 1
- If required files are missing when using `--fields`, the script exits with error code 1
- If any operation fails, the script reports it in the summary and exits with error code 1
- Organization creation failures are logged as warnings but don't stop the process (unless using `--org-only`)

## Exit Codes

- `0` - Success (all operations completed successfully)
- `1` - Failure (missing files, failed operations, or other errors)

## Notes

- The project name is automatically extracted from the last part of the folder path
- The script uses the refactored modular `api_senders` package for better code organization
- All file paths are resolved relative to the provided `folder_path`
- The script includes improved error handling and retry logic compared to the original version

