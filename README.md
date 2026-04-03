![Void Tool](https://i.ibb.co/nsQrjW07/9bbd5859-0ac8-43c3-8a06-92a841d5e70a.png)

#  Void

>  Advanced Web Application Security Scanner for Bug Bounty Hunters & Security Researchers

---

##  Overview

**Void** is a powerful and intelligent web security scanner designed to automate vulnerability discovery in modern web applications.
It combines smart crawling, deep parameter discovery, and advanced fuzzing techniques to identify real-world security issues.

---

##  Features

###  Smart Crawling Engine

* Crawl websites with depth control
* Parse `sitemap.xml` & `robots.txt`
* Detect:

  * Admin panels
  * Login pages
  * Upload forms
  * API endpoints

---

###  Advanced Parameter Discovery

* Extract parameters from:

  * URLs
  * Forms
  * JavaScript files
  * APIs & JSON responses
  * Headers & cookies

---

###  Powerful Fuzzing Engine

* Dynamic payload generation
* Payload mutation:

  * Encoding
  * Obfuscation
  * Bypass techniques
* Context-aware fuzzing

---

###  Vulnerability Detection

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Local File Inclusion (LFI)
* Command Injection
* SSRF
* IDOR

---

###  High Performance

* Async scanning using `aiohttp`
* High concurrency
* Smart retry & timeout handling

---

###  JavaScript Analyzer

* Extract hidden endpoints
* Detect API keys & tokens
* Identify sensitive data leaks

---

###  Technology Fingerprinting

* Detect:

  * Frameworks
  * CMS
  * Server technologies
  * Programming languages

---

###  Modular Architecture

* Plugin-based system
* Easily extendable modules

---

###  Reporting

* Generate reports in:

  * HTML
  * JSON
  * Markdown
  * PDF
  * CSV
* Includes:

  * Vulnerability details
  * Evidence
  * Risk levels

---

###  Desktop GUI

* Full graphical interface (PyQt5)
* Charts, scan history, and settings
* Optional model-assisted analysis (API key stored in local settings)

---

##  Installation

```bash
git clone https://github.com/yourusername/void.git
cd void
pip install -r requirements.txt
```

**Notes (Windows):**

* Some optional dependencies (e.g. `pygraphviz`, `scapy`) may need extra system tools (Graphviz, Npcap). See `requirements.txt` comments if install fails.
* Selenium requires a matching Chrome / ChromeDriver setup for browser-based features.

---

##  Usage

The main entry file in this repository is **`void.py`**.

### GUI mode

```bash
python void.py --gui
```

Or launch without a URL (opens the GUI):

```bash
python void.py
```

### CLI scan

```bash
python void.py https://example.com --profile deep
```

Optional: model-assisted analysis (configure API key in **Settings** or `config.yaml`):

```bash
python void.py https://example.com --profile deep --remote
```

### Report output

```bash
python void.py https://example.com --profile standard --format json -o report.json
```

Supported formats: `html`, `json`, `csv`, `markdown`, `pdf`.

### Other flags

* `--threads`, `--depth`, `--timeout` — tune the scan
* `-v` / `-q` — verbose / quiet

---

###  Profiles

* `quick` → Fast scan
* `standard` → Balanced
* `deep` → Full scan
* `stealth` → Low detection
* `aggressive` → Maximum speed
* `api` → API-focused profile

---

##  Configuration

On first run, the app creates a user data directory and loads/saves settings there.

**Default paths:**

| Item | Location |
|------|----------|
| Config | `~/.voidstrike/config.yaml` (Windows: `%USERPROFILE%\.voidstrike\config.yaml`) |
| Database | `~/.voidstrike/voidstrike.db` |
| Logs | `~/.voidstrike/voidstrike.log` |
| Reports | `~/.voidstrike/reports/` |

API keys and preferences saved from the **Settings** screen are written to `config.yaml` (not embedded in source code).

---

## 📸 Screenshots
![Void Tool](https://i.ibb.co/wF1ZhXcs/Ekran-g-r-nt-s-2026-04-03-225956.png)
>

---

## 🛣️ Roadmap

* [ ] Reduce false positives
* [ ] Smart payload learning (AI-based)
* [ ] Advanced WAF bypass
* [ ] Authentication support (JWT, sessions)
* [ ] GUI improvements
* [ ] Real-time dashboard
* [ ] Distributed scanning

---

## ⚠️ Disclaimer

> ❗ This tool is created for **educational purposes** and **authorized security testing only**.

* Do NOT use this tool on systems you do not own or have explicit permission to test.
* The developer is **not responsible** for any misuse or damage caused.

---

## 📄 License

This project is licensed under the MIT License.

---

## ⭐ Support

If you like this project:

* ⭐ Star the repo
* 🐛 Report bugs
* 💡 Suggest features

---

## 👨‍💻 Developer

**mkaf7h**  
Group: **groupnukersec**  
Telegram: **@truemkaf7h**

---

##  Final Note

> "Accuracy > Speed | Intelligence > Noise | Real Exploits > Guessing"
