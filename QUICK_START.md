# 🚀 Quick Start Guide

## Clone and Run

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/blackmirror.git
cd blackmirror

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Start scanning!
python3 blackmirror.py example.com
```

## 🎯 Basic Usage

### Full Reconnaissance Scan
```bash
python3 blackmirror.py example.com
```

### Module-Specific Scans
```bash
# Port scanning only
python3 blackmirror.py example.com --ports

# Web reconnaissance only
python3 blackmirror.py example.com --web

# SSL analysis only
python3 blackmirror.py example.com --ssl

# Vulnerability scanning only
python3 blackmirror.py example.com --vulns

# Passive reconnaissance only
python3 blackmirror.py example.com --passive
```

### Export Reports
```bash
# Export as Markdown
python3 blackmirror.py example.com --export markdown

# Export as HTML
python3 blackmirror.py example.com --export html

# Export as JSON
python3 blackmirror.py example.com --export json
```

### Automation Mode
```bash
# Silent mode for scripting
python3 blackmirror.py example.com --quiet --json
```

## 🧪 Testing

### View Demo
```bash
python3 demo.py
```

### Run Test Suite
```bash
python3 test_blackmirror.py
```

### Get Help
```bash
python3 blackmirror.py --help
```

## ⚙️ Configuration

### Set API Keys (Optional)
```bash
export SHODAN_API_KEY="your-shodan-api-key"
export CENSYS_API_ID="your-censys-api-id"
export CENSYS_API_SECRET="your-censys-api-secret"
```

### Edit Configuration
```bash
nano config.yaml
```

## 📊 Sample Output

```
┌─[🔍 Port Scan]───────────────────────────────────────────┐
│ Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)            │
│ Service Fingerprint: Apache 2.4.29, Ubuntu, OpenSSH 8.2 │
└──────────────────────────────────────────────────────────┘

┌─[🕵️ Web Recon]──────────────────────────────────────────┐
│ Tech: Apache, PHP 7.4, Bootstrap, jQuery                │
│ Headers: X-Powered-By: PHP/7.4, Server: Apache          │
│ Interesting Files: robots.txt, .git/, backup.zip        │
└──────────────────────────────────────────────────────────┘

┌─[🛡️ Vulnerabilities]────────────────────────────────────┐
│ CVE-2021-41773 (Apache Path Traversal) – ⚠️ Patch now    │
│ CVE-2022-23307 (Log4j) – 🛡 Not detected                 │
└──────────────────────────────────────────────────────────┘
```

## 🔧 Troubleshooting

### Missing Dependencies
```bash
pip3 install -r requirements.txt
```

### Missing External Tools
```bash
# Install nmap
sudo apt install nmap

# Install nuclei (optional)
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

### Permission Issues
```bash
chmod +x blackmirror.py
chmod +x demo.py
chmod +x test_blackmirror.py
```

## 🛡️ Legal Notice

- Only scan targets you own or have explicit permission to test
- Use for educational and authorized security testing only
- Comply with local laws and regulations
- Report vulnerabilities responsibly

## 📞 Support

- **Issues**: GitHub Issues
- **Documentation**: README.md
- **Demo**: python3 demo.py
- **Tests**: python3 test_blackmirror.py

---

**Created by R Muhamme Thoufeel**

*blackmirror - Because reconnaissance should be beautiful, not boring.* 