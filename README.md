✅ README.md
# 🛡️ VirusTotal API Scanner

This is a simple Python-based CLI tool that scans **file hashes** and **IP addresses** using the [VirusTotal API v3](https://developers.virustotal.com/reference). It provides threat intelligence by querying VirusTotal's database and showing detection results in a clean format.

---

## 📸 Screenshot

![VirusTotal Scanner CLI Output](screenshots/vt-scanner-demo.png)

---

## ⚙️ Features

- 🔍 Check if a **file hash (MD5/SHA1/SHA256)** is malicious
- 🌐 Check if an **IP address** is blacklisted
- 📊 Displays detection stats and specific malicious scan engine results
- 🧩 Modular structure with clear separation (`main.py`, `utils.py`, `config.py`)
- 🔐 Secure API handling (no key exposed in code)

---

## 🚀 Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/virustotal-api-scanner.git
cd virustotal-api-scanner
2. Install Dependencies
No external dependencies beyond requests.
pip install requests

3. Configure Your API Key
Create a config.py file in the project root:
API_KEY = "your_virustotal_api_key"

HEADERS = {
    "x-apikey": API_KEY
}

BASE_URL = "https://www.virustotal.com/api/v3"

✅ How to Use
Run the tool:
python main.py
You’ll be prompted to select an option:

 === VirusTotal API Scanner ===
1. Check File Hash
2. Check IP Address
Choose an option:
Then input your desired file hash or IP to check the threat report.

📁 Project Structure
├── main.py             # CLI interface
├── utils.py            # API logic
├── config.py           # Your API key (DO NOT SHARE)
├── .gitignore
├── README.md
└── screenshots/
    └── vt-scanner-demo.png


📌 Disclaimer
This tool is for educational and non-commercial purposes only. Do not use it to scan third-party data without consent. Always follow VirusTotal's terms of service.

👨‍💻 Author
Ahmed Raza
🔗 GitHub: @raza360ahmed

🌟 Support
Give a ⭐ on GitHub if you found this project helpful!
