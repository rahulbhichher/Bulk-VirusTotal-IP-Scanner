# Bulk-VirusTotal-IP-Scanner

A Python project for scanning IP addresses using the VirusTotal API. This tool collects reputation data, vendor reports, and geolocation details for each IP address.

## Features
- Scans a list of IP addresses from a CSV file.
- Provides real-time results of IP analysis.
- Retrieves vendor-specific reports and geolocation information.
- Outputs results to a CSV file.

## Requirements
- Python 3.8+
- `aiohttp`
- `nest_asyncio`
- `pandas`
- `requests`
- `python-dotenv`

## Installation
1. Clone the repository:
```bash
$ git clone https://github.com/YourUsername/Bulk-VirusTotal-IP-Scanner.git
$ cd Bulk-VirusTotal-IP-Scanner
```

2. Install dependencies:
```bash
$ pip install -r requirements.txt
```

3. Create a `.env` file with your VirusTotal API key:
```
VT_API_KEY=your_api_key_here
```

## Usage
1. Prepare a CSV file named `input.csv` with a column `ip` containing the IP addresses to scan.

2. Run the script:
```bash
$ python virustotal_ip_scanner.py
```

3. Upload your `input.csv` file when prompted.

4. The results will be saved to `output.csv` and automatically downloaded (if running in Google Colab).

## Output Format
The resulting CSV file contains the following columns:
- `ip` - The scanned IP address.
- `status` - Whether the IP is marked as `Malicious`, `Harmless`, or `Error`.
- `malicious_votes` - Number of vendors marking the IP as malicious.
- `harmless_votes` - Number of vendors marking the IP as harmless.
- `country` - Country where the IP is located.
- `region` - Region where the IP is located.
- `city` - City where the IP is located.
- `vendor_report` - List of vendors who flagged the IP as malicious.

## License
GPL-3.0 License

## Contribution
Feel free to fork this repository and contribute to the project.

## Author
Rahul Bhichher

