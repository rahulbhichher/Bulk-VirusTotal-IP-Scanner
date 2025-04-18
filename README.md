# BULK-VIRUSTOTAL-IP-SCANNER
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/github/license/rahulbhichher/Bulk-VirusTotal-IP-Scanner)
![Stars](https://img.shields.io/github/stars/rahulbhichher/Bulk-VirusTotal-IP-Scanner?style=social)

## 📌 Description
BULK-VIRUSTOTAL-IP-SCANNER is a powerful and user-friendly Python3 tool for scanning a list of IP addresses using the VirusTotal API. It provides comprehensive threat intelligence, reputation data, and detailed analysis reports for each IP address, including vendor-specific detections.

## 🚀 Features
- **Cross-Platform Compatibility:** Works on Linux, Windows, MacOS, and Google Colab.
- **Automatic Dependency Installation:** Automatically installs missing packages with progress bars.
- **Automatic Environment Detection:** Uses appropriate methods to select files based on the platform.
- **Personalized User Interaction:** Greets the user with their hostname and OS information.
- **Rate Limit Detection:** Alerts the user if the VirusTotal API rate limit is reached.
- **Detailed Information Retrieval:** Retrieves ASN, ISP, Network, Country, Reputation, Tags, Whois, Detected Vendors, and Malicious Reports.
- **CSV Output:** Saves results to `output.csv` with all gathered information.
- **Real-Time Progress Bar:** Shows progress of IP scanning.

## 📂 Requirements
The following packages are required and will be installed automatically if missing:
- `requests`
- `pandas`
- `termcolor`
- `tqdm`
- `tabulate`

## 📥 Installation
You can download the code from the GitHub repository and simply run it. Dependencies will be installed automatically.

### Manual Installation (Optional):
```bash
pip3 install requests pandas termcolor tqdm tabulate
```

## 🔧 Usage
1. **Clone the Repository:**
```bash
git clone https://github.com/rahulbhichher/BULK-VIRUSTOTAL-IP-SCANNER.git
```

2. **Navigate to the Directory:**
```bash
cd BULK-VIRUSTOTAL-IP-SCANNER
```

3. **Run the Script:**
```bash
python3 BULK-VIRUSTOTAL-IP-SCANNER.py
```

4. **Provide your VirusTotal API Key:**
- Your API key will be saved locally for future use.

5. **Upload your IP list CSV file:**
- The file must contain a column named `ip`.

6. **View Results:**
- Results will be saved to `output.csv` in the same directory.
- For Google Colab users, the file will be automatically downloaded.

## 🌍 Platform-Specific Notes
- **Linux:** Uses `zenity` for file selection. (If not installed, install via `sudo apt-get install zenity`)
- **Windows:** Uses `PowerShell` for file selection.
- **MacOS:** Uses `tkinter` if available.
- **Google Colab:** Uses `google.colab.files` for file upload and download.

## 🔒 API Key Handling
- Your VirusTotal API key is securely saved locally in a text file `vt_api_key.txt`.
- You only need to provide it once unless you want to change it later.

## ⚠️ Disclaimer
**This tool is provided for educational and research purposes only.**
Please use it responsibly and ethically. By using this tool, you agree to:
- Use the VirusTotal API strictly in accordance with [VirusTotal’s Terms of Service](https://support.virustotal.com/hc/en-us/articles/115002168385-Terms-of-Service).
- **Avoid any commercial or corporate use unless you have an enterprise license** from VirusTotal.
- Respect the privacy and data protection policies when handling IP addresses or scan results.
The author assumes no responsibility for misuse, abuse, or legal issues arising from the use of this tool.

## 📜 License
This project is licensed under the GPL-3.0 License.

## ✍️ Author
Developed by Rahul Bhichher
