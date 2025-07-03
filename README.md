
# 🛰️ webcaptured - The OSINT Tool

---

## 🚀 Overview

This project is an **Advanced OSINT Tool** designed to gather and analyze publicly available intelligence from a given website or domain.  
It automates key reconnaissance and scanning tasks such as:

- Email, phone number, and hyperlink extraction  
- WHOIS information retrieval  
- IP address intelligence  
- Subdomain enumeration  
- Exposure to info-stealer malware (Cavalier check)

Built for efficiency, modularity, and stealth.

---

## 🧩 Project Structure

```

.
├── main.py                 # Entry point of the tool
├── core/                   # Core modules
│   ├── banner.py           # Displays fancy ASCII banner
│   ├── connection.py       # Internet connectivity checker
│   ├── validation.py       # URL validation
│   ├── scraper.py          # Scrapes emails, phones, and links
│   ├── save.py             # Saves results locally
│   │── port_scanner.py     # Scans open ports on target
│   ├── screenshot.py         # Takes screenshots of target websites
│   ├── subdomain_enum.py     # Enumerates subdomains of a target domain
│   ├── whois_lookup.py       # Retrieves WHOIS data
│   ├── ip_info.py            # Retrieves IP address details
│   ├── cavalier_check.py     # Detects exposure to info-stealer malware
 
├── osint/                  # OSINT-specific modules
│   ├── whois\_lookup.py     # WHOIS data retrieval
│   ├── ip\_info.py          # IP info extraction
│   ├── subdomain\_enum.py   # Subdomain enumeration
│   ├── cavalier\_check.py   # Checks for info-stealer exposure
├── test/                   # Placeholder for test scripts
├── requirements.txt        # Python dependencies

````

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/ibrahmsql/webcaptured.git
cd webcaptured 
pip install -r requirements.txt
````

---

## 💡 Usage

Run the tool from the terminal with desired flags:

```bash
python main.py --url https://example.com \
               --emails \
               --phones \
               --links \
               --whois \
               --ipinfo \
               --subdomains \
               --check-stealer \
               --save output_folder
```

### 🔍 Available Flags

| Flag              | Description                            |
| ----------------- | -------------------------------------- |
| `--url`           | Target domain or website               |
| `--emails`        | Extract email addresses                |
| `--phones`        | Extract phone numbers                  |
| `--links`         | Extract hyperlinks                     |
| `--whois`         | Perform WHOIS lookup                   |
| `--ipinfo`        | Fetch IP address details               |
| `--subdomains`    | Enumerate subdomains                   |
| `--check-stealer` | Check exposure to info-stealer malware |
| `--save`          | Save results to specified folder       |

---

## 🛡️ Features

* 🔍 Deep scraping of targets
* 🌐 WHOIS + IP intelligence
* 🕵️ Subdomain discovery
* ☣️ Info-stealer threat exposure checks
* 📁 Output saving to local storage
* 💻 CLI-native with modular architecture

---

## 🧠 Ideal For

* Security Analysts
* Red Team Operators
* OSINT Investigators
* Threat Intelligence Researchers

---

## 📦 Dependencies

* `requests`
* `beautifulsoup4`
* `python-whois`

Install all via:

```bash
pip install -r requirements.txt
```

---

## ⚔️ Future Enhancements

* [ ] Integration with Shodan or Censys API
* [ ] Passive DNS collection
* [ ] PDF & CSV reporting
* [ ] GUI frontend (optional)

---

<!-- Author Section -->
<section id="author" style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin-top: 40px; text-align: center;">
  <h2>👨‍💻 Author</h2>
  <p>
    Created by <a href="https://github.com/ibrahmsql" target="_blank" rel="noopener noreferrer" style="text-decoration:none; color:#0366d6;">
    <strong>ibrahimsql</strong></a> —<br>
    Crafted with precision and passion.<br>
    <em>"Think like a hacker. Move like a shadow."</em>
  </p>
</section>


## 🧭 Disclaimer

This tool is intended for **educational and authorized penetration testing** only.
Unauthorized use against targets without explicit permission is **strictly prohibited**.

---

