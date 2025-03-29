# Project: BULK-VIRUSTOTAL-IP-SCANNER
# Description: A Python tool for scanning a list of IP addresses using the VirusTotal API to gather threat intelligence, reputation data, and detailed analysis reports.
# Author: Rahul Bhichher
# Version: 1.0
# License: GPL-3.0 License

import subprocess
import sys
import requests
import pandas as pd
import os
import platform
import socket
from termcolor import colored
from tqdm import tqdm
from tabulate import tabulate

try:
    from google.colab import files
    IN_COLAB = True
except ImportError:
    IN_COLAB = False

API_KEY_FILE = "vt_api_key.txt"
REQUIRED_PACKAGES = ['requests', 'pandas', 'termcolor', 'tqdm', 'tabulate']


def install(package):
    try:
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            subprocess.check_call([sys.executable, '-m', 'pip3', 'install', package, '--user', '--quiet'])
        elif sys.platform.startswith('win'):
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', package, '--user', '--quiet'])
    except Exception as e:
        print(colored(f"Failed to install {package}. Error: {e}", "red"))


def check_and_install_packages():
    missing_packages = []
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(colored("\nInstalling missing packages...", "yellow"))
        for package in tqdm(missing_packages, desc="Installing Dependencies", ncols=75):
            install(package)
        print(colored("\nAll required packages are installed successfully!", "green"))


def greet_user():
    hostname = socket.gethostname()
    os_name = platform.system()
    print(colored(f"\nHello {hostname}, Welcome to BULK-VIRUSTOTAL-IP-SCANNER running on {os_name}.", "green"))


def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as file:
        file.write(api_key)


def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as file:
            return file.read().strip()
    return None


def check_ip(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 429:
        print(colored("\nAPI Rate Limit Reached!", "red"))
        return 'RATE_LIMIT_REACHED'
    if response.status_code == 200:
        return response.json()
    return None


def scan_ip_list(api_key, csv_file):
    df = pd.read_csv(csv_file)
    if 'ip' not in df.columns:
        print(colored("Error: The CSV file must contain a column named 'ip'.", "red"))
        return

    results = []
    for ip in tqdm(df['ip'], desc="Scanning IPs", ncols=75):
        response = check_ip(api_key, ip)
        if response == 'RATE_LIMIT_REACHED':
            break
        if response:
            attributes = response.get('data', {}).get('attributes', {})
            last_analysis_results = attributes.get('last_analysis_results', {})
            detected_vendors = [vendor for vendor, data in last_analysis_results.items() if data['category'] == 'malicious']

            results.append({
                'IP': ip,
                'ASN': attributes.get('asn', 'Unknown'),
                'ISP': attributes.get('isp', 'Unknown'),
                'Network': attributes.get('network', 'Unknown'),
                'Country': attributes.get('country', 'Unknown'),
                'Reputation': attributes.get('reputation', 'Unknown'),
                'Malicious Reports': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                'Detected Vendors': detected_vendors,
                'Tags': attributes.get('tags', []),
                'Whois': attributes.get('whois', 'Not Available')
            })

    if results:
        print(colored("\nSummary of Scanned IPs:", "cyan"))
        print(tabulate(results, headers="keys", tablefmt="grid"))

    pd.DataFrame(results).to_csv('output.csv', index=False)

    if IN_COLAB:
        try:
            files.download('output.csv')
        except Exception as e:
            print(colored(f"Error downloading file: {e}", "red"))


def main():
    greet_user()
    check_and_install_packages()
    api_key = load_api_key()
    if not api_key:
        api_key = input("Enter your VirusTotal API key: ")
        save_api_key(api_key)
        print("API key saved successfully!")

    csv_file = input("Enter the full path of your CSV file: ")
    if not os.path.exists(csv_file):
        print(colored("File not found. Please try again.", "red"))
        sys.exit(1)

    scan_ip_list(api_key, csv_file)
    print(colored("\nThank you for using BULK-VIRUSTOTAL-IP-SCANNER!", "green"))


if __name__ == "__main__":
    main()
