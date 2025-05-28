# Attack Surface Scanner

A Python-based tool for scanning and managing attack surface data, including IPs, ports, subdomains, and API endpoints.

## Features

- IP address scanning and geolocation
- Port scanning and management
- Subdomain enumeration
- API endpoint discovery
- Alive host detection
- Integration with external API for data storage

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the application:
   - Copy `config.py.example` to `config.py`
   - Update the configuration values in `config.py` with your settings

## Configuration

The following configuration values need to be set in `config.py`:

- `API_BASE_URL`: Base URL for the API endpoints
- `API_KEY`: API key for authentication
- `PROXY_HOST`: SOCKS5 proxy host (if using proxy)
- `PROXY_PORT`: SOCKS5 proxy port (if using proxy)

## Usage

Run the scanner with:
```bash
python send_attack_surface_results.py <project_id> <folder_path>
```

Where:
- `project_id`: The ID of the project to associate the results with
- `folder_path`: Path to the folder containing the scan results files

## Input Files

The scanner expects the following files in the specified folder:
- `ips.txt`: List of IP addresses
- `ports.txt`: List of ports in IP:PORT format
- `subdomains.txt`: List of subdomains
- `api.txt`: List of API endpoints
- `alive.txt`: List of alive hosts

## Security

- Never commit `config.py` to version control
- Keep your API keys and credentials secure
- Use appropriate access controls for the API endpoints 