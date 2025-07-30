#!/usr/bin/env python3
"""
Demo script for blackmirror - shows capabilities with sample data
"""

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

def demo_port_scan():
    """Demo port scan results"""
    console.print(Panel.fit(
        """[bold blue]🔍 Port Scan Results[/bold blue]

[bold]Open Ports:[/bold] 22 (SSH), 80 (HTTP), 443 (HTTPS), 3306 (MySQL)

[bold]Service Detection:[/bold]
  • Port 22: OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
  • Port 80: Apache httpd 2.4.29 ((Ubuntu))
  • Port 443: Apache httpd 2.4.29 ((Ubuntu))
  • Port 3306: MySQL 8.0.32-0ubuntu0.20.04.2

[bold]OS Detection:[/bold] Linux 5.4.0-74-generic (Ubuntu 20.04.3 LTS)""",
        title="🔍 Port Scan",
        border_style="blue"
    ))

def demo_web_recon():
    """Demo web reconnaissance results"""
    console.print(Panel.fit(
        """[bold green]🕵️ Web Reconnaissance[/bold green]

[bold]Technologies Detected:[/bold]
  • Apache 2.4.29
  • PHP 7.4.3
  • WordPress 5.8.2
  • Bootstrap 4.6.0
  • jQuery 3.6.0
  • MySQL 8.0.32

[bold]Interesting Headers:[/bold]
  • X-Powered-By: PHP/7.4.3
  • Server: Apache/2.4.29 (Ubuntu)
  • X-Frame-Options: SAMEORIGIN
  • X-Content-Type-Options: nosniff

[bold]Interesting Files:[/bold]
  • robots.txt
  • wp-config.php
  • .htaccess
  • backup.zip
  • admin.php""",
        title="🕵️ Web Recon",
        border_style="green"
    ))

def demo_ssl_analysis():
    """Demo SSL analysis results"""
    console.print(Panel.fit(
        """[bold yellow]🛡️ SSL/TLS Analysis[/bold yellow]

[bold]Certificate Information:[/bold]
  • Issuer: Let's Encrypt Authority X3
  • Subject: CN=example.com
  • Valid Until: 2024-01-15 12:00:00 UTC
  • Serial Number: 03:4a:5b:6c:7d:8e:9f:10

[bold]Cipher Analysis:[/bold]
  • Strong Ciphers: 12
  • Weak Ciphers: 0
  • Vulnerabilities: 0

[bold]SSL Vulnerabilities:[/bold]
  ✅ No SSL vulnerabilities detected""",
        title="🛡️ SSL Analysis",
        border_style="yellow"
    ))

def demo_vulnerabilities():
    """Demo vulnerability scan results"""
    console.print(Panel.fit(
        """[bold red]🛡️ Vulnerability Assessment[/bold red]

[bold red]Critical Vulnerabilities:[/bold red]
  • CVE-2021-41773 - Apache Path Traversal
    - Description: Apache 2.4.49-2.4.50 path traversal vulnerability
    - Remediation: Update Apache to version 2.4.51 or later

[bold orange]High Risk Vulnerabilities:[/bold orange]
  • CVE-2022-23307 - Apache Log4j
    - Description: Log4j remote code execution vulnerability
    - Remediation: Update Log4j to version 2.17.1 or later

[bold yellow]Medium Risk Vulnerabilities:[/bold yellow]
  • Default SSH Configuration
    - Description: SSH allows root login and password authentication
    - Remediation: Disable root login and use key-based authentication

[bold blue]Low Risk Vulnerabilities:[/bold blue]
  • Information Disclosure - robots.txt
    - Description: robots.txt file exposes sensitive directories
    - Remediation: Review and secure exposed directories""",
        title="🛡️ Vulnerabilities",
        border_style="red"
    ))

def demo_passive_recon():
    """Demo passive reconnaissance results"""
    console.print(Panel.fit(
        """[bold cyan]🌐 Passive Reconnaissance[/bold cyan]

[bold]WHOIS Information:[/bold]
  • Registrar: GoDaddy.com, LLC
  • Created: 2020-03-15
  • Expires: 2024-03-15
  • Status: Active

[bold]DNS Records:[/bold]
  • A Records: 192.168.1.10
  • MX Records: mail.example.com
  • NS Records: ns1.example.com, ns2.example.com
  • TXT Records: v=spf1 include:_spf.google.com ~all

[bold]Geolocation:[/bold]
  • Country: United States
  • City: San Francisco
  • ISP: Cloudflare, Inc.
  • AS: AS13335 Cloudflare, Inc.""",
        title="🌐 Passive Recon",
        border_style="cyan"
    ))

def demo_summary():
    """Demo executive summary"""
    table = Table(title="📊 Executive Summary", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    table.add_column("Status", style="green")
    
    table.add_row("Open Ports", "4", "⚠️")
    table.add_row("Critical Vulnerabilities", "1", "🔴")
    table.add_row("High Risk Vulnerabilities", "1", "🟠")
    table.add_row("Medium Risk Vulnerabilities", "1", "🟡")
    table.add_row("Low Risk Vulnerabilities", "1", "🟢")
    table.add_row("Web Technologies", "6", "ℹ️")
    table.add_row("SSL Vulnerabilities", "0", "✅")
    
    console.print(table)

def demo_usage():
    """Show usage examples"""
    console.print(Panel.fit(
        """[bold]Usage Examples:[/bold]

[bold]Basic Scan:[/bold]
  python blackmirror.py example.com

[bold]Module-Specific Scans:[/bold]
  python blackmirror.py example.com --ports
  python blackmirror.py example.com --web
  python blackmirror.py example.com --ssl
  python blackmirror.py example.com --vulns
  python blackmirror.py example.com --passive

[bold]Report Export:[/bold]
  python blackmirror.py example.com --export markdown
  python blackmirror.py example.com --export html
  python blackmirror.py example.com --export json

[bold]Automation:[/bold]
  python blackmirror.py example.com --quiet --json""",
        title="💡 Usage Examples",
        border_style="blue"
    ))

def main():
    """Run the demo"""
    console.print("\n🔥 blackmirror Demo\n", style="bold red")
    console.print("This demo shows the capabilities of blackmirror with sample data.\n")
    
    # Show each module demo
    demo_port_scan()
    console.print()
    
    demo_web_recon()
    console.print()
    
    demo_ssl_analysis()
    console.print()
    
    demo_vulnerabilities()
    console.print()
    
    demo_passive_recon()
    console.print()
    
    demo_summary()
    console.print()
    
    demo_usage()
    console.print()
    
    console.print(Panel.fit(
        """[bold green]🎉 Demo Complete![/bold green]

To run a real scan:
  python blackmirror.py example.com

To test the installation:
  python test_blackmirror.py

For more information:
  cat README.md""",
        title="🚀 Next Steps",
        border_style="green"
    ))

if __name__ == '__main__':
    main() 