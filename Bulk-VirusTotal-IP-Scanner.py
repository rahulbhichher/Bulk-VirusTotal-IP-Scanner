# Project: BULK-VIRUSTOTAL-IP-SCANNER
# Description: A Python tool for scanning a list of IP addresses using the VirusTotal API to gather threat intelligence, reputation data, and detailed analysis reports.
# Author: Rahul Bhichher
# Version: 1.0
# License: GPL-3.0 License

import subprocess
import sys
import requests
import pandas as pd
import time
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
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def check_and_install_packages():
    missing_packages = []
    for package in REQUIRED_PACKAGES:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(colored("\nMissing packages detected. Installing them now...", "yellow"))
        for package in tqdm(missing_packages, desc="Installing Dependencies", ncols=75):
            install(package)
        print(colored("\nAll required packages have been installed successfully!", "green"))


def get_file():
    platform_name = sys.platform
    file_path = None

    try:
        if IN_COLAB:
            print(colored("\nPlease upload your CSV file...", "yellow"))
            uploaded = files.upload()
            if uploaded:
                file_path = list(uploaded.keys())[0]
            else:
                print(colored("No file uploaded. Exiting...", "red"))
                sys.exit(1)

        elif platform_name.startswith('linux'):
            try:
                file_path = subprocess.check_output(['zenity', '--file-selection', '--file-filter=*.csv']).decode('utf-8').strip()
            except FileNotFoundError:
                print(colored("Zenity is not installed. Please install it using: sudo apt-get install zenity", "red"))
                sys.exit(1)
        elif platform_name.startswith('win'):
            command = r'powershell -Command "[System.Reflection.Assembly]::LoadWithPartialName(\"System.windows.forms\") | Out-Null; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Filter = \"CSV Files (*.csv)|*.csv\"; $f.ShowDialog() | Out-Null; $f.FileName"'
            file_path = subprocess.check_output(command, shell=True).decode('utf-8').strip()
        elif platform_name.startswith('darwin'):
            import tkinter as tk
            from tkinter import filedialog
            root = tk.Tk()
            root.withdraw()
            file_path = filedialog.askopenfilename(title="Select your IP list CSV file", filetypes=[("CSV Files", "*.csv")])
    except Exception as e:
        print(colored(f"Error occurred during file selection: {e}", "red"))
        sys.exit(1)

    if not file_path:
        print(colored("No file selected. Exiting...", "red"))
        sys.exit(1)

    return file_path


def save_api_key(api_key):
    with open(API_KEY_FILE, "w") as file:
        file.write(api_key)


def load_api_key():
    if os.path.exists(API_KEY_FILE):
        with open(API_KEY_FILE, "r") as file:
            return file.read().strip()
    return None


def download_output():
    if IN_COLAB:
        try:
            files.download('output.csv')
            print(colored("\nOutput file downloaded successfully!", "green"))
        except Exception as e:
            print(colored(f"\nError in downloading the file: {e}", "red"))


def greet_user():
    hostname = socket.gethostname()
    os_name = platform.system()
    print(colored(f"\nHello {hostname}, Welcome to BULK-VIRUSTOTAL-IP-SCANNER running on {os_name}.", "green"))


def check_ip(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 429:
        print(colored("\nAPI Rate Limit Reached! Please try again later or use a different API key.", "red"))
        return 'RATE_LIMIT_REACHED'
    if response.status_code == 200:
        return response.json()
    else:
        return None


def scan_ip_list(api_key, csv_file):
    df = pd.read_csv(csv_file)
    if 'ip' not in df.columns:
        print("Error: CSV file must contain a column named 'ip'.")
        return

    results = []
    bad_ips = []
    for ip in tqdm(df['ip'], desc="Scanning IPs", ncols=75):
        response = check_ip(api_key, ip)
        if response == 'RATE_LIMIT_REACHED':
            break
        if response:
            attributes = response.get('data', {}).get('attributes', {})
            detected_vendors = [vendor for vendor, data in attributes.get('last_analysis_results', {}).items() if data['category'] == 'malicious']

            result_data = {
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
            }

            if result_data['Malicious Reports'] > 0:
                bad_ips.append(result_data)

            results.append(result_data)

    pd.DataFrame(results).to_csv('output.csv', index=False)
    download_output()

    if bad_ips:
        print(colored("\nSummary of IPs with Bad Reputation:", "red"))
        print(tabulate(bad_ips, headers="keys", tablefmt="grid"))


def main():
    greet_user()
    check_and_install_packages()
    api_key = load_api_key()
    if not api_key:
        api_key = input("Enter your VirusTotal API key: ")
        save_api_key(api_key)
        print("API key saved successfully!")

    csv_file = get_file()
    scan_ip_list(api_key, csv_file)
    print(colored("\nGoodbye! Thank you for using BULK-VIRUSTOTAL-IP-SCANNER!", "green"))


if __name__ == "__main__":
    main()
