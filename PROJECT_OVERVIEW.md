# 🔥 blackmirror - Project Overview

## 🎯 What is blackmirror?

**blackmirror** is a powerful, modular, and hacker-centric Linux tool that automates the entire reconnaissance and vulnerability scanning workflow for a given IP address or domain.

Built to eliminate the boring, repetitive parts of ethical hacking, bug bounties, CTFs, and red team ops — blackmirror gives you all the critical information in one terminal command.

## 🏗️ Architecture

### Core Components

```
blackmirror/
├── blackmirror.py          # Main CLI application
├── modules/                # Modular scanning components
│   ├── __init__.py
│   ├── config.py           # Configuration management
│   ├── port_scanner.py     # Port scanning with nmap
│   ├── web_recon.py        # Web technology fingerprinting
│   ├── ssl_analyzer.py     # SSL/TLS certificate analysis
│   ├── vuln_scanner.py     # Vulnerability scanning
│   ├── passive_recon.py    # WHOIS, Shodan, Censys
│   └── report_generator.py # Report generation
├── requirements.txt         # Python dependencies
├── setup.py               # Installation script
├── install.sh             # Automated installation
├── test_blackmirror.py    # Test suite
├── demo.py                # Capability demonstration
└── README.md              # Comprehensive documentation
```

### Module Breakdown

| Module | Purpose | Key Features |
|--------|---------|--------------|
| **Port Scanner** | Fast port discovery | nmap integration, service detection, OS fingerprinting |
| **Web Recon** | Technology fingerprinting | Header analysis, file discovery, directory enumeration |
| **SSL Analyzer** | Certificate inspection | Cipher analysis, vulnerability checks, protocol support |
| **Vuln Scanner** | Vulnerability assessment | nuclei integration, custom checks, misconfiguration detection |
| **Passive Recon** | External intelligence | WHOIS, DNS, Shodan, Censys, geolocation |
| **Report Generator** | Output formatting | Markdown, HTML, JSON export |

## 🚀 Key Features

### 🔍 Comprehensive Scanning
- **Port Scanning**: Fast discovery with service and version detection
- **Web Reconnaissance**: Technology fingerprinting and file discovery
- **SSL/TLS Analysis**: Certificate inspection and cipher analysis
- **Vulnerability Assessment**: CVE detection and misconfiguration checks
- **Passive Reconnaissance**: External intelligence gathering

### 🎨 Beautiful Output
- **Rich CLI Interface**: Colorized, organized terminal output
- **Progress Indicators**: Real-time scanning progress
- **Modular Display**: Organized sections for each scan type
- **Export Options**: Markdown, HTML, and JSON reports

### ⚙️ Modular Design
- **Plugin Architecture**: Easy to extend with new modules
- **Configuration Management**: YAML-based settings
- **API Integration**: Shodan, Censys, VirusTotal support
- **Custom Checks**: Extensible vulnerability detection

### 🔧 Automation Ready
- **JSON Output**: Machine-readable for scripting
- **Quiet Mode**: Silent operation for automation
- **Custom Configs**: Environment-specific settings
- **Batch Processing**: Multiple target support

## 📊 Usage Examples

### Basic Scan
```bash
python blackmirror.py example.com
```

### Module-Specific Scans
```bash
python blackmirror.py example.com --ports --web --vulns
```

### Report Export
```bash
python blackmirror.py example.com --export markdown
python blackmirror.py example.com --export html
python blackmirror.py example.com --export json
```

### Automation
```bash
python blackmirror.py example.com --quiet --json
```

## 🛠️ Installation

### Quick Install
```bash
git clone https://github.com/yourusername/blackmirror.git
cd blackmirror
./install.sh
```

### Manual Install
```bash
pip install -r requirements.txt
chmod +x blackmirror.py
```

### Dependencies
- **Python 3.8+**
- **nmap** - Port scanning
- **nuclei** - Vulnerability scanning
- **whatweb** - Web technology detection (optional)

## 🔧 Configuration

### Environment Variables
```bash
export SHODAN_API_KEY="your-key"
export CENSYS_API_ID="your-id"
export CENSYS_API_SECRET="your-secret"
```

### Configuration File (config.yaml)
```yaml
scanning:
  port_scan_timeout: 30
  web_scan_timeout: 10
  max_threads: 10

apis:
  shodan_api_key: ""
  censys_api_id: ""
  censys_api_secret: ""

tools:
  nmap_path: "nmap"
  nuclei_path: "nuclei"
```

## 📈 Sample Output

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

[+] Report saved to: recon-192.168.1.10.md
```

## 🧪 Testing

### Run Test Suite
```bash
python test_blackmirror.py
```

### View Demo
```bash
python demo.py
```

## 🔒 Security Considerations

### Legal Usage
- Only scan targets you own or have explicit permission to test
- Respect rate limits and terms of service
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Ethical Guidelines
- Use for educational and authorized security testing only
- Do not use for malicious purposes
- Respect privacy and data protection laws
- Report vulnerabilities responsibly

## 🚀 Roadmap

### Planned Features
- [ ] Subdomain enumeration
- [ ] Cloud service detection
- [ ] Container scanning
- [ ] API endpoint discovery
- [ ] Custom vulnerability templates
- [ ] Integration with more tools (masscan, dirb, etc.)
- [ ] Web application firewall detection
- [ ] Cloud misconfiguration checks

### Future Enhancements
- [ ] Web interface
- [ ] Database storage
- [ ] Team collaboration features
- [ ] Automated remediation suggestions
- [ ] Integration with SIEM systems

## 🤝 Contributing

We welcome contributions! Areas for contribution:

- **New Modules**: Add new scanning capabilities
- **Bug Fixes**: Improve reliability and accuracy
- **Documentation**: Enhance guides and examples
- **Testing**: Add comprehensive test coverage
- **Performance**: Optimize scanning speed

## 📞 Support

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Documentation**: Wiki pages
- **Community**: Security community forums

## 📝 License

MIT License - see LICENSE file for details.

---

**Made with ❤️ for the security community**

*blackmirror - Because reconnaissance should be beautiful, not boring.* 